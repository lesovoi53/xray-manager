"""Disposable native systemd proof; never touches actual OpenFlux services."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[1]


def ctl(*args, check=True):
    return subprocess.run(['systemctl', *args], capture_output=True, text=True, check=check, timeout=15).stdout.strip()


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError('bounded systemd wait timed out')


def main():
    assert os.geteuid() == 0 and Path('/.x-manager-test-lab').is_file()
    assert Path('/run/systemd/container').read_text().strip() == 'systemd-nspawn'
    name = 'qa-openflux-budget@'
    units = tuple(name + str(i) + '.service' for i in range(1, 9))
    template = Path('/etc/systemd/system/' + name + '.service')
    assert not template.exists() and not template.is_symlink()
    for unit in units:
        assert ctl('show', unit, '-p', 'LoadState', '--value') == 'not-found'
        assert not Path('/etc/systemd/system/' + unit + '.d').exists()
    spec = importlib.util.spec_from_file_location('lab_shared', SOURCE / 'scripts/openflux-watchdog.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    cases = []
    with tempfile.TemporaryDirectory(prefix='qa-openflux-budget-') as directory:
        qa = Path(directory)
        wrapper = qa / 'gate.py'
        # Imported by both this test and the real ExecCondition subprocess.
        wrapper.write_text('''import contextlib, importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('shared', %r)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.UNITS = %r
m.CONFIG = %r
m.STATE = %r
m.LOCK = %r
m.HOOK = %r
class Controller:
    def conflicts(self): return []
    def allowed(self, unit): return not Path(%r).exists()
    def status(self, unit): return {'off': False}
    def lock(self): return contextlib.nullcontext()
if __name__ == '__main__':
    import sys
    try: ok = m.Watchdog(controller=Controller()).gate(sys.argv[-1])
    except Exception: ok = False
    raise SystemExit(0 if ok else 1)
''' % (str(SOURCE / 'scripts/openflux-watchdog.py'), units, str(qa / 'config.json'),
       str(qa / 'state.json'), str(qa / 'lock'), str(wrapper), str(qa / 'stopped')))
        fixture = qa / 'fixture.py'
        fixture.write_text('''from pathlib import Path
import sys, time
p = Path(__file__).parent
slot = sys.argv[1]
with (p / ('starts-' + slot)).open('a') as f: f.write('start\\n')
while not (p / ('crash-' + slot)).exists(): time.sleep(.02)
raise SystemExit(1)
''')
        setup = importlib.util.spec_from_file_location('qa_gate', wrapper)
        gate = importlib.util.module_from_spec(setup)
        setup.loader.exec_module(gate)
        module = gate.m
        watchdog = module.Watchdog(controller=gate.Controller())
        template.write_text('[Unit]\nDescription=Disposable shared OpenFlux budget fixture\n[Service]\n'
                            'Type=simple\nExecStart=/usr/bin/python3 ' + str(fixture) + ' %i\nRestart=no\n')

        def starts(slot):
            path = qa / ('starts-' + str(slot))
            return len(path.read_text().splitlines()) if path.exists() else 0

        def prop(slot, key):
            return ctl('show', units[slot - 1], '-p', key, '--value')

        try:
            ctl('daemon-reload')
            watchdog.configure(3, 1)
            assert all(prop(i, 'ActiveState') == 'inactive' for i in range(1, 9))
            ctl('start', *units[:3])
            wait_for(lambda: all(starts(i) == 1 for i in (1, 2, 3)))
            assert watchdog.status()['spent'] == 0
            healthy_pid = prop(3, 'MainPID')
            cases.append('eight-policies-no-activation-initial-starts-uncharged')
            for slot in (1, 2):
                (qa / ('crash-' + str(slot))).touch()
            wait_for(lambda: watchdog.status()['spent'] == 3
                     and all(prop(i, 'ActiveState') == 'inactive' for i in (1, 2)))
            assert starts(1) + starts(2) == 5, (starts(1), starts(2), watchdog.status())
            assert prop(3, 'MainPID') == healthy_pid
            assert all(starts(i) == 0 for i in range(4, 9))
            # systemd can garbage-collect inactive template instances, clearing
            # Result/NRestarts; persistent group state remains authoritative.
            cases.append('two-simultaneous-crashes-exactly-three-shared-retries-healthy-unchanged')
            counts = [prop(i, 'NRestarts') for i in (1, 2)]
            assert watchdog.configure(3, 1)['changed'] == []
            for slot in (1, 2):
                assert not watchdog.gate(units[slot - 1])
            time.sleep(1.3)
            assert [prop(i, 'NRestarts') for i in (1, 2)] == counts
            assert starts(1) + starts(2) == 5 and watchdog.status()['spent'] == 3
            cases.append('repeat-config-and-exhausted-gates-no-refill-no-restart-loop')
            watchdog.reset()
            assert all(prop(i, 'ActiveState') == 'inactive' for i in (1, 2))
            assert prop(3, 'MainPID') == healthy_pid
            (qa / 'crash-1').unlink()
            # Garbage-collected instances already have NRestarts=0; unlike
            # failed loaded units they do not accept reset-failed by name.
            ctl('start', units[0])
            wait_for(lambda: prop(1, 'ActiveState') == 'active')
            assert prop(1, 'NRestarts') == '0' and watchdog.status()['spent'] == 0
            # Start a fresh recovery sequence without a persistent crash flag.
            # The following health restart must clear a nonzero NRestarts too.
            before = starts(1)
            ctl('kill', '--signal=KILL', '--kill-whom=main', units[0])
            wait_for(lambda: starts(1) == before + 1 and prop(1, 'ActiveState') == 'active')
            assert prop(1, 'NRestarts') == '1' and watchdog.status()['spent'] == 1
            before = starts(1)
            assert watchdog.reserve(units[0], 'health-test')
            ctl('restart', units[0])
            wait_for(lambda: starts(1) == before + 1)
            assert prop(1, 'NRestarts') == '0' and watchdog.status()['spent'] == 2
            cases.append('explicit-reset-no-start-manual-start-free-health-restart-charged-once')
            ctl('stop', units[0])
            before = starts(1)
            (qa / 'stopped').touch()
            assert not watchdog.reserve(units[0], 'stopped-health')
            assert not watchdog.gate(units[0])
            assert watchdog.configure(3, 1)['changed'] == []
            time.sleep(1.3)
            assert prop(1, 'ActiveState') == 'inactive' and starts(1) == before
            assert watchdog.status()['spent'] == 2
            cases.append('manual-stop-inhibit-preserved')
        except Exception:
            for unit in units[:3]:
                print(ctl('show', unit, '-p', 'ActiveState', '-p', 'NRestarts', '-p', 'InvocationID', '-p', 'Result'))
                print(subprocess.run(['journalctl', '-u', unit, '-n', '15', '--no-pager'], capture_output=True, text=True).stdout)
            raise
        finally:
            ctl('stop', *units, check=False)
            for unit in units:
                path = Path('/etc/systemd/system/' + unit + '.d')
                (path / module.DROPIN).unlink(missing_ok=True)
                if path.exists():
                    path.rmdir()
            template.unlink()
            ctl('daemon-reload')
            ctl('reset-failed', *units, check=False)
    assert ctl('show', units[0], '-p', 'LoadState', '--value') == 'not-found'
    cases.append('isolated-fixtures-removed')
    print(json.dumps({'passed': True, 'systemd': ctl('--version').splitlines()[0], 'cases': cases}, indent=2))


if __name__ == '__main__':
    main()
