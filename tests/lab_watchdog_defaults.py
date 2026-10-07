"""Disposable nspawn lab: real systemd defaults, manual stop, finite crashes."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[1]


def ctl(*args, check=True):
    return subprocess.run(['systemctl', *args], text=True, capture_output=True, check=check, timeout=15).stdout.strip()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def wait_for(predicate, seconds=8):
    end = time.monotonic()+seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError('bounded wait timed out')


def main():
    assert os.geteuid() == 0
    assert Path('/.x-manager-test-lab').is_file()
    assert Path('/run/systemd/container').read_text().strip() == 'systemd-nspawn'
    unit = Path('/etc/systemd/system/wdtt.service')
    dropin = Path(str(unit)+'.d')
    assert not unit.exists() and not unit.is_symlink() and not dropin.exists(), 'refuse existing wdtt fixture'
    assert ctl('show', 'wdtt.service', '-p', 'LoadState', '--value') == 'not-found', 'refuse installed wdtt'
    wd = module('lab_defaults', SOURCE/'scripts/tuna-watchdog.py')
    lc = module('lab_defaults_lifecycle', SOURCE/'scripts/service-control.py')
    cases = []
    with tempfile.TemporaryDirectory(prefix='qa-watchdog-defaults-') as directory:
        qa = Path(directory)
        fixture = qa/'fixture.py'
        fixture.write_text('''from pathlib import Path
import time
p = Path(__file__).parent
with (p/'starts').open('a') as f: f.write('started\\n')
while not (p/'crash').exists(): time.sleep(.05)
raise SystemExit(1)
''')
        controller = lc.Controller(root=qa/'lifecycle')
        wd.lifecycle = lambda: controller
        wd.UNITS = ['wdtt']
        wd.BACKUPS = qa
        unit.write_text('[Unit]\nDescription=Disposable bounded defaults fixture\n[Service]\n'
                        'Type=simple\nExecStart=/usr/bin/python3 '+str(fixture)+'\nRestart=no\n')
        try:
            ctl('daemon-reload')
            result = wd.defaults(2, 1)
            assert result['changed'] == ['wdtt']
            assert ctl('show', 'wdtt', '-p', 'ActiveState', '--value') == 'inactive'
            cases.append('defaults-install-without-activation')
            (qa/'crash').touch()
            ctl('start', 'wdtt')
            wait_for(lambda: ctl('show', 'wdtt', '-p', 'ActiveState', '--value') == 'failed'
                     and ctl('show', 'wdtt', '-p', 'NRestarts', '--value') == '3')
            starts = (qa/'starts').read_text().splitlines()
            assert len(starts) == 3, starts
            cases.append('two-crash-retries-exhaust-after-three-starts')
            assert wd.defaults(2, 1)['changed'] == []
            time.sleep(1.3)
            assert ctl('show', 'wdtt', '-p', 'ActiveState', '--value') == 'failed'
            assert ctl('show', 'wdtt', '-p', 'NRestarts', '--value') == '3'
            assert (qa/'starts').read_text().splitlines() == starts
            cases.append('repeated-defaults-do-not-reset-exhaustion')
            # Explicitly reset only our exhausted disposable fixture.
            (qa/'crash').unlink()
            ctl('reset-failed', 'wdtt')
            ctl('start', 'wdtt')
            wait_for(lambda: len((qa/'starts').read_text().splitlines()) == 4)
            pid = ctl('show', 'wdtt', '-p', 'MainPID', '--value')
            assert wd.defaults(2, 1)['changed'] == []
            assert ctl('show', 'wdtt', '-p', 'MainPID', '--value') == pid
            cases.append('repeat-preserves-policy-and-running-pid')
            ctl('stop', 'wdtt')
            time.sleep(1.3)
            assert ctl('show', 'wdtt', '-p', 'ActiveState', '--value') == 'inactive'
            assert len((qa/'starts').read_text().splitlines()) == 4
            cases.append('manual-stop-does-not-restart')
        except Exception:
            print(ctl('show', 'wdtt.service', '-p', 'ActiveState', '-p', 'Result', '-p', 'NRestarts', '-p', 'StartLimitBurst', '-p', 'StartLimitIntervalUSec'))
            print(subprocess.run(['journalctl', '-u', 'wdtt.service', '-n', '20', '--no-pager'], capture_output=True, text=True).stdout)
            raise
        finally:
            ctl('stop', 'wdtt', check=False)
            (dropin/wd.NAME).unlink(missing_ok=True)
            if dropin.exists():
                dropin.rmdir()
            unit.unlink()
            ctl('daemon-reload')
            ctl('reset-failed', 'wdtt', check=False)
        assert ctl('show', 'wdtt', '-p', 'LoadState', '--value') == 'not-found'
        cases.append('fixture-removed')
    print(json.dumps({'passed': True, 'cases': cases, 'systemd': ctl('--version').splitlines()[0]}, indent=2))


if __name__ == '__main__':
    main()
