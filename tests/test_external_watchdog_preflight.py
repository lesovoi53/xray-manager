"""Maintenance refuses active external pollers before any managed mutation."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('watchdog_guard_state', ROOT/'scripts/installer-state.py')
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)


class ExternalWatchdogPreflight(unittest.TestCase):
    def shell_preflight(self, active='', status='3', reported='inactive'):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            (fixture/'os-release').write_text('ID=debian\nVERSION_ID=13\n')
            (fixture/'systemd').mkdir()
            # Only filesystem endpoints are redirected. Execute the real
            # production xm_preflight, including its call to the watcher guard.
            common = (ROOT/'scripts/installer-common.sh').read_text()
            common = common.replace('. /etc/os-release', '. '+shlex.quote(str(fixture/'os-release')))
            common = common.replace('/run/systemd/system', str(fixture/'systemd'))
            common = common.replace('/run/lock/x-manager-install.lock', str(fixture/'install.lock'))
            script = common + r'''
systemctl() {
    printf '%s\n' "$*" >> "$FIXTURE/commands"
    if [ "$2" = "$ACTIVE" ]; then printf '%s\n' active; return 0; fi
    printf '%s\n' "$REPORTED"
    return "$STATUS"
}
uname() { printf '%s\n' x86_64; }
flock() { :; }
xm_preflight
printf '%s\n' passed
'''
            result = subprocess.run(['bash', '-c', script], text=True, capture_output=True,
                                    env=dict(os.environ, FIXTURE=temporary, ACTIVE=active, STATUS=status, REPORTED=reported))
            return result, (fixture/'commands').read_text(), (fixture/'install.lock').exists()

    def test_real_shell_preflight_refuses_each_active_poller_before_lock_write(self):
        for unit in ('vpn-watchdog.service', 'vpn-watchdog.timer'):
            with self.subTest(unit=unit):
                result, commands, lock_created = self.shell_preflight(active=unit)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Explicitly stop the external watcher', result.stderr)
                self.assertFalse(lock_created)
                self.assertTrue(all(line.startswith('is-active ') for line in commands.splitlines()))

    def test_real_shell_preflight_accepts_inactive_and_missing_watchers(self):
        for status, reported in (('3', 'inactive'), ('4', 'unknown')):
            with self.subTest(status=status):
                result, commands, lock_created = self.shell_preflight(status=status, reported=reported)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('passed', result.stdout)
                self.assertTrue(lock_created)
                self.assertEqual(commands.splitlines(), ['is-active vpn-watchdog.service', 'is-active vpn-watchdog.timer'])

    def test_real_shell_preflight_fails_closed_on_query_error_or_transition(self):
        for status, reported in (('1', ''), ('3', 'activating'), ('3', 'deactivating')):
            with self.subTest(status=status, reported=reported):
                result, _, lock_created = self.shell_preflight(status=status, reported=reported)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(lock_created)

    def test_direct_restore_refuses_before_read_stop_or_write(self):
        for active in ('vpn-watchdog.service', 'vpn-watchdog.timer'):
            calls = []

            def system(args, **kwargs):
                calls.append(args)
                self.assertEqual(args[:2], ['systemctl', 'is-active'])
                return subprocess.CompletedProcess(args, 0 if args[2] == active else 3,
                                                   stdout='active' if args[2] == active else 'inactive', stderr='')

            with self.subTest(active=active), patch.object(state.subprocess, 'run', side_effect=system), \
                    patch.object(Path, 'read_text') as read, patch.object(Path, 'unlink') as unlink, \
                    patch.object(state.shutil, 'rmtree') as remove:
                with self.assertRaisesRegex(RuntimeError, 'Explicitly stop the external watcher'):
                    state.restore(Path('/unused-readonly-guard-fixture'))
                read.assert_not_called()
                unlink.assert_not_called()
                remove.assert_not_called()
                self.assertTrue(calls)

    def test_direct_restore_rejects_query_error_before_snapshot_read(self):
        result = subprocess.CompletedProcess([], 1, stdout='', stderr='synthetic unavailable bus')
        with patch.object(state.subprocess, 'run', return_value=result), patch.object(Path, 'read_text') as read:
            with self.assertRaisesRegex(RuntimeError, 'Cannot verify external watcher'):
                state.restore(Path('/unused-readonly-guard-fixture'))
            read.assert_not_called()

    def test_direct_restore_accepts_inactive_watchers_without_touching_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary)
            (backup/'state.json').write_text(json.dumps({'services': {}, 'paths': [], 'databases': []}))
            (backup/'iptables').write_text('')
            with tarfile.open(backup/'files.tar', 'w'):
                pass
            calls = []

            def system(args, **kwargs):
                calls.append(tuple(args))
                if args[:2] == ['systemctl', 'is-active']:
                    return subprocess.CompletedProcess(args, 3, stdout='inactive', stderr='')
                if args[:2] == ('systemctl', 'show'):
                    return subprocess.CompletedProcess(args, 0, stdout='not-found', stderr='')
                self.assertIn(tuple(args), [('systemctl', 'daemon-reload'), ('iptables-restore',)])
                return subprocess.CompletedProcess(args, 0, stdout='', stderr='')

            with patch.object(state.subprocess, 'run', side_effect=system):
                state.restore(backup)
            self.assertEqual(calls[:2], [('systemctl', 'is-active', 'vpn-watchdog.service'),
                                        ('systemctl', 'is-active', 'vpn-watchdog.timer')])
            self.assertFalse(any(len(c) > 1 and c[1] in ('stop', 'disable', 'restart') for c in calls))


if __name__ == '__main__':
    unittest.main()
