"""Disposable nspawn Debian 13 only. Real systemd failures, no VPS or installer."""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import time

UNIT = 'xm-snell6-qa.service'
ROOT = Path('/opt/xm-snell6-systemd-qa-v4')
CONFIG = ROOT / 'config.json'
UNIT_PATH = Path('/etc/systemd/system') / UNIT
SOURCE_CORE = Path('/opt/snell6-qualification-20261005/sing-box')
CORE = ROOT / 'sing-box'


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=15)


def ctl(*args, check=True):
    return command('systemctl', *args, check=check)


def state():
    fields = ('ActiveState', 'SubState', 'MainPID', 'Result', 'NRestarts', 'ExecMainStatus')
    output = ctl('show', UNIT, '--property=' + ','.join(fields)).stdout
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)


def wait(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = state()
        if predicate(value):
            return value
        time.sleep(.1)
    raise AssertionError('systemd state timeout: ' + repr(state()))


def clean_stop():
    ctl('stop', UNIT)
    wait(lambda s: s['MainPID'] == '0' and s['ActiveState'] in ('inactive', 'failed'))
    ctl('reset-failed', UNIT)


def main():
    assert Path('/.x-manager-test-lab').is_file(), 'requires disposable lab marker'
    assert Path('/run/systemd/container').read_text().strip() == 'systemd-nspawn'
    assert 'VERSION_ID="13"' in Path('/etc/os-release').read_text()
    assert not UNIT_PATH.exists(), 'refusing to overwrite existing unit'
    user = pwd.getpwnam('snell')
    ROOT.mkdir(mode=0o750)
    os.chown(ROOT, 0, user.pw_gid)
    shutil.copyfile(SOURCE_CORE, CORE)
    CORE.chmod(0o755)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    valid = {'log': {'level': 'error'}, 'inbounds': [
        {'type': 'snell', 'listen': '127.0.0.1', 'listen_port': port,
         'version': 6, 'mode': 'default', 'psk': 'synthetic-systemd-only-key'}],
        'outbounds': [{'type': 'direct', 'tag': 'fixture-only'}]}
    def config(text):
        CONFIG.write_text(text)
        os.chown(CONFIG, 0, user.pw_gid)
        CONFIG.chmod(0o640)
    config(json.dumps(valid))
    unit = f'''[Unit]
Description=Disposable Snell v6 acceptance
StartLimitIntervalSec=infinity
StartLimitBurst=3

[Service]
Type=exec
User=snell
Group={pwd.getpwnam('snell').pw_name}
ExecStartPre={CORE} check -c {CONFIG}
ExecStart={CORE} run -c {CONFIG}
Restart=on-failure
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
'''
    UNIT_PATH.write_text(unit)
    (ROOT / 'tested.service').write_text(unit)
    rows = []
    started = time.monotonic()
    try:
        command('systemd-analyze', 'verify', str(UNIT_PATH))
        ctl('daemon-reload')
        ctl('enable', UNIT)
        ctl('start', UNIT)
        healthy = wait(lambda s: s['ActiveState'] == 'active' and int(s['MainPID']) > 0)
        pid = int(healthy['MainPID'])
        # Type=exec is not a readiness signal: wait for the actual listener.
        for attempt in range(30):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    break
            except OSError:
                if attempt == 29:
                    raise
                time.sleep(.1)
        assert Path('/proc') .joinpath(str(pid)).stat().st_uid == user.pw_uid
        rows.append({'case': 'start-listener-nonroot', 'passed': True, 'state': healthy})
        clean_stop()
        assert not Path('/proc', str(pid)).exists()
        time.sleep(1.3)
        assert state()['ActiveState'] == 'inactive'
        rows.append({'case': 'manual-stop-no-restart-no-main-process', 'passed': True})

        config('{ invalid json')
        rejected = ctl('start', UNIT, check=False)
        assert rejected.returncode != 0, 'invalid configuration reported success'
        failed = wait(lambda s: s['ActiveState'] == 'failed')
        journal = command('journalctl', '-u', UNIT, '--no-pager', '-o', 'cat').stdout
        assert 'invalid' in journal.lower() or 'decode' in journal.lower()
        rows.append({'case': 'invalid-config-rejected', 'passed': True, 'exit': rejected.returncode, 'state': failed})
        clean_stop()
        config(json.dumps(valid))

        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', port))
            occupied.listen()
            ctl('start', UNIT, check=False)
            failed = wait(lambda s: s['ActiveState'] == 'failed')
            journal = command('journalctl', '-u', UNIT, '--no-pager', '-o', 'cat').stdout
            assert 'address already in use' in journal.lower()
            rows.append({'case': 'occupied-port-fails-visibly', 'passed': True, 'state': failed})
        clean_stop()

        ctl('start', UNIT)
        pids = []
        for attempt in range(3):
            running = wait(lambda s: s['ActiveState'] == 'active' and int(s['MainPID']) > 0 and int(s['MainPID']) not in pids)
            pids.append(int(running['MainPID']))
            ctl('kill', '--kill-whom=main', '--signal=SIGKILL', UNIT)
        failed = wait(lambda s: s['ActiveState'] == 'failed')
        assert int(failed['NRestarts']) == 3, 'unexpected restart count'
        journal = command('journalctl', '-u', UNIT, '--no-pager', '-o', 'cat').stdout
        assert 'Start request repeated too quickly.' in journal.split('process ' + str(pids[-1]))[-1]
        time.sleep(2.2)
        assert state()['MainPID'] == '0' and state()['ActiveState'] == 'failed'
        assert all(not Path('/proc', str(p)).exists() for p in pids)
        rows.append({'case': 'initial-plus-two-restarts-then-stops', 'passed': True, 'successful_starts': len(pids), 'state': failed})
        clean_stop()
        ctl('start', UNIT)
        wait(lambda s: s['ActiveState'] == 'active')
        rows.append({'case': 'explicit-reset-allows-recovery', 'passed': True})
    except Exception as e:
        rows.append({'case': 'execution', 'passed': False, 'error': type(e).__name__ + ': ' + str(e)})
    finally:
        ctl('stop', UNIT)
        last = state()
        assert last['MainPID'] == '0'
        journal = command('journalctl', '-u', UNIT, '--no-pager', '-o', 'cat').stdout
        (ROOT / 'journal.log').write_text(journal)
        ctl('disable', UNIT)
        UNIT_PATH.unlink()
        ctl('daemon-reload')
        ctl('reset-failed', UNIT, check=False)
        CONFIG.unlink()
        summary = {'passed': len(rows) == 6 and all(r['passed'] for r in rows),
                   'cases': rows, 'seconds': round(time.monotonic()-started, 2),
                   'systemd': command('systemctl', '--version').stdout.splitlines()[0],
                   'final_main_pid': last['MainPID']}
        (ROOT / 'results.json').write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary), flush=True)
    return 0 if summary['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
