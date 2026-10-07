"""Laboratory-only Snell v6 installer/rollback prototype. Not a release installer.

Requires the existing disposable Debian 13 nspawn lab. Never accepts VPS paths.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path('/opt/xm-snell6-transaction-qa')
UNIT = 'xm-snell6-transaction-qa.service'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
SOURCE = Path('/opt/snell6-qualification-20261005/sing-box')
HASH = '187965235a83a462aa10291cfab561d0caed2fde90a608e6899b17aed9e01ea8'
MANAGED = [ROOT/'sing-box', ROOT/'config.json', ROOT/'identity.json', ROOT/'release.txt', UNIT_PATH]


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, capture_output=True, timeout=15)


def ctl(*args, check=True):
    return run('systemctl', *args, check=check)


def active():
    return ctl('is-active', '--quiet', UNIT, check=False).returncode == 0


def atomic(path, data, mode, gid=0):
    fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def ready(port):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if active():
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    return
            except OSError:
                pass
        time.sleep(.1)
    raise RuntimeError('service readiness failed')


def digest_state():
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None for p in MANAGED}


def install(release, fail_after_files=False, invalid_candidate=False):
    user = pwd.getpwnam('snell')
    assert hashlib.sha256(SOURCE.read_bytes()).hexdigest() == HASH, 'candidate hash mismatch'
    identity_path = ROOT/'identity.json'
    if identity_path.exists():
        identity_bytes = identity_path.read_bytes()
        identity = json.loads(identity_bytes)
        config_bytes = (ROOT/'config.json').read_bytes()
    else:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        assert port not in (443, 8443)
        identity = dict(name='Synthetic name & unchanged', port=port, psk='synthetic-transaction-key')
        identity_bytes = json.dumps(identity).encode()
        config_bytes = json.dumps({'log': {'level': 'error'}, 'inbounds': [
            {'type': 'snell', 'listen': '127.0.0.1', 'listen_port': port, 'version': 6,
             'mode': 'default', 'psk': identity['psk']}], 'outbounds': [{'type': 'direct'}]}).encode()
    unit = f'''[Unit]
Description=Disposable transactional Snell v6
[Service]
Type=exec
User=snell
Group=snell
ExecStartPre={ROOT}/sing-box check -c {ROOT}/config.json
ExecStart={ROOT}/sing-box run -c {ROOT}/config.json
Restart=no
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
'''.encode()
    candidate = {MANAGED[0]: (SOURCE.read_bytes(), 0o755, 0),
                 MANAGED[1]: (config_bytes, 0o640, user.pw_gid),
                 MANAGED[2]: (identity_bytes, 0o600, 0),
                 MANAGED[3]: ((release+'\n').encode(), 0o644, 0),
                 MANAGED[4]: (unit, 0o644, 0)}
    with tempfile.TemporaryDirectory(dir=ROOT, prefix='validation-') as temp:
        staged = Path(temp)/'config.json'
        staged.write_bytes(b'{invalid' if invalid_candidate else config_bytes)
        run(str(SOURCE), 'check', '-c', str(staged))
    if all(p.exists() and p.read_bytes() == data for p, (data, _, _) in candidate.items()):
        return {'changed': False, 'backup': None}
    backup = Path(tempfile.mkdtemp(prefix='backup-', dir=ROOT))
    backup.chmod(0o700)
    previous = {'active': active(), 'enabled': ctl('is-enabled', '--quiet', UNIT, check=False).returncode == 0,
                'files': []}
    for index, p in enumerate(MANAGED):
        entry = {'path': str(p), 'exists': p.exists(), 'snapshot': str(index)}
        if p.exists():
            stat = p.stat()
            entry.update(mode=stat.st_mode & 0o777, gid=stat.st_gid)
            shutil.copyfile(p, backup/str(index))
        previous['files'].append(entry)
    (backup/'state.json').write_text(json.dumps(previous))
    try:
        for p, (data, mode, gid) in candidate.items():
            atomic(p, data, mode, gid)
        if fail_after_files:
            raise RuntimeError('injected failure after managed-file replacement')
        ctl('daemon-reload')
        if not previous['files'][0]['exists'] or previous['enabled']:
            ctl('enable', UNIT)
        if not previous['files'][0]['exists'] or previous['active']:
            ctl('restart', UNIT)
            ready(identity['port'])
        return {'changed': True, 'backup': backup.name}
    except Exception as failure:
        try:
            ctl('daemon-reload')
            if UNIT_PATH.exists():
                ctl('stop', UNIT)
                if not previous['enabled']:
                    ctl('disable', UNIT)
            for entry in previous['files']:
                p = Path(entry['path'])
                if entry['exists']:
                    atomic(p, (backup/entry['snapshot']).read_bytes(), entry['mode'], entry['gid'])
                elif p.exists():
                    p.unlink()
            ctl('daemon-reload')
            if previous['active']:
                ctl('start', UNIT)
                ready(identity['port'])
        except Exception as rollback:
            raise RuntimeError('ROLLBACK FAILED; preserve backup '+backup.name) from rollback
        raise RuntimeError('Update failed; managed files and service restored; backup '+backup.name) from failure


def main():
    assert Path('/.x-manager-test-lab').exists()
    assert Path('/run/systemd/container').read_text().strip() == 'systemd-nspawn'
    assert 'VERSION_ID="13"' in Path('/etc/os-release').read_text()
    assert platform.machine() == 'x86_64'
    assert not ROOT.exists() and not UNIT_PATH.exists(), 'refusing to overwrite earlier lab state'
    ROOT.mkdir(mode=0o750)
    os.chown(ROOT, 0, pwd.getpwnam('snell').pw_gid)
    rows = []
    started = time.monotonic()
    with (ROOT/'lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            first = install('lab-package-1')
            assert first['changed'] and active()
            rows.append({'case': 'clean-install', 'passed': True})
            before = digest_state()
            pid = ctl('show', UNIT, '--property=MainPID', '--value').stdout.strip()
            assert install('lab-package-1')['changed'] is False
            assert digest_state() == before and ctl('show', UNIT, '--property=MainPID', '--value').stdout.strip() == pid
            rows.append({'case': 'repeat-no-file-or-process-change', 'passed': True})
            result = install('lab-package-2')
            after = digest_state()
            assert result['changed'] and active()
            assert all(after[str(p)] == before[str(p)] for p in MANAGED if p.name != 'release.txt')
            rows.append({'case': 'update-preserves-config-identity-port-key', 'passed': True})
            try:
                install('lab-package-3', fail_after_files=True)
            except RuntimeError as error:
                assert 'restored' in str(error)
            else:
                raise AssertionError('injected failure was hidden')
            assert digest_state() == after and active()
            rows.append({'case': 'partial-replacement-rollback-exact-files-active-service', 'passed': True})
            try:
                install('lab-package-3', invalid_candidate=True)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError('invalid candidate accepted')
            assert digest_state() == after and active()
            rows.append({'case': 'invalid-candidate-before-mutation', 'passed': True})
            ctl('stop', UNIT)
            install('lab-package-3')
            assert not active()
            assert digest_state()[str(ROOT/'identity.json')] == after[str(ROOT/'identity.json')]
            rows.append({'case': 'stopped-service-remains-stopped-after-update', 'passed': True})
        except Exception as error:
            rows.append({'case': 'execution', 'passed': False, 'error': type(error).__name__+': '+str(error)})
        finally:
            if UNIT_PATH.exists():
                ctl('stop', UNIT)
                ctl('disable', UNIT)
                UNIT_PATH.unlink()
                ctl('daemon-reload')
            summary = {'passed': len(rows) == 6 and all(r['passed'] for r in rows), 'cases': rows,
                       'seconds': round(time.monotonic()-started, 2), 'binary_sha256': HASH,
                       'scope': 'same binary, different laboratory package markers; no subscription DB'}
            (ROOT/'results.json').write_text(json.dumps(summary, indent=2))
            print(json.dumps(summary), flush=True)
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
