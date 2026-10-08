"""Maintenance tests use real transaction code and a stateful systemd boundary."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('watchdog_guard_state', ROOT/'scripts/installer-state.py')
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)
TIMER, SERVICE = state.EXTERNAL_WATCHDOGS


class ExternalWatchdogMaintenance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.backup = self.root/'backup'
        self.backup.mkdir()
        (self.backup/'state.json').write_text(json.dumps({'services': {}, 'paths': [], 'databases': []}))
        (self.backup/'iptables').write_text('')
        with tarfile.open(self.backup/'files.tar', 'w'):
            pass
        self.marker = self.root/'maintenance.json'
        self.units = {unit: dict(LoadState='loaded', ActiveState='active', UnitFileState='enabled')
                      for unit in state.EXTERNAL_WATCHDOGS}
        self.calls = []
        self.fail = None
        self.addCleanup(patch.stopall)
        patch.object(state, 'MAINTENANCE', self.marker).start()
        patch.object(state.subprocess, 'run', side_effect=self.system).start()

    def system(self, args, **kwargs):
        args = list(args)
        self.calls.append(args)
        if args[:2] == ['systemctl', 'show']:
            self.assertEqual(kwargs['timeout'], 30)
            return subprocess.CompletedProcess(args, 0, stdout='\n'.join(k+'='+v for k, v in self.units[args[2]].items()))
        if args[:2] in (['systemctl', 'start'], ['systemctl', 'stop']):
            self.assertTrue(self.marker.exists(), 'intent must be durable before any stop/start')
            self.assertEqual(kwargs['timeout'], 30)
            if self.fail == tuple(args[1:]):
                return subprocess.CompletedProcess(args, 1, stdout='', stderr='synthetic failure')
            self.units[args[2]]['ActiveState'] = 'active' if args[1] == 'start' else 'inactive'
            return subprocess.CompletedProcess(args, 0, stdout='')
        self.assertIn(args, [['systemctl', 'daemon-reload'], ['iptables-restore']])
        return subprocess.CompletedProcess(args, 0, stdout='')

    def changes(self):
        return [args[1:] for args in self.calls if len(args) > 1 and args[1] in ('start', 'stop', 'enable', 'disable', 'restart')]

    def test_success_preserves_order_and_enablement(self):
        state.watchdog_preflight()
        self.assertFalse(self.marker.exists())
        state.watchdog_pause(self.backup)
        original = json.loads(self.marker.read_text())
        self.assertEqual(original['backup'], str(self.backup))
        self.assertEqual(original['units'][SERVICE]['ActiveState'], 'active')
        state.watchdog_resume()
        self.assertEqual(self.changes(), [['stop', TIMER], ['stop', SERVICE], ['start', SERVICE], ['start', TIMER]])
        self.assertFalse(self.marker.exists())

    def test_stopped_disabled_masked_and_missing_not_started(self):
        for load, enabled in [('loaded', 'disabled'), ('masked', 'masked'), ('not-found', '')]:
            for unit in self.units:
                self.units[unit].update(LoadState=load, UnitFileState=enabled, ActiveState='inactive')
            state.watchdog_pause(self.backup)
            state.watchdog_resume()
        self.assertEqual(self.changes(), [])

    def test_active_timer_inactive_service(self):
        self.units[SERVICE]['ActiveState'] = 'inactive'
        state.watchdog_pause(self.backup)
        state.watchdog_resume()
        self.assertEqual(self.changes(), [['stop', TIMER], ['start', TIMER]])

    def test_partial_pause_failure(self):
        self.fail = ('stop', SERVICE)
        with self.assertRaisesRegex(RuntimeError, 'Cannot stop'):
            state.watchdog_pause(self.backup)
        self.fail = None
        state.watchdog_resume()
        self.assertEqual(self.changes(), [['stop', TIMER], ['stop', SERVICE], ['start', TIMER]])
        self.assertFalse(self.marker.exists())

    def test_stop_timeout_keeps_recovery_marker(self):
        actual = self.system
        def timeout(args, **kwargs):
            if list(args)[:2] == ['systemctl', 'stop']:
                raise subprocess.TimeoutExpired(args, 30)
            return actual(args, **kwargs)
        with patch.object(state.subprocess, 'run', side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                state.watchdog_pause(self.backup)
        self.assertTrue(self.marker.exists())
        state.watchdog_resume()

    def test_restore_failure_is_recoverable_and_idempotent(self):
        state.watchdog_pause(self.backup)
        self.fail = ('start', TIMER)
        with self.assertRaisesRegex(RuntimeError, 'Cannot start'):
            state.watchdog_resume()
        self.assertTrue(self.marker.exists())
        self.fail = None
        state.watchdog_resume()
        self.assertEqual(self.changes().count(['start', SERVICE]), 1)
        self.assertFalse(self.marker.exists())

    def test_interrupted_marker_blocks_overwrite(self):
        state.watchdog_pause(self.backup)
        before = self.marker.read_bytes()
        with self.assertRaisesRegex(RuntimeError, '--recover-watchdog'):
            state.watchdog_pause(self.backup)
        self.assertEqual(self.marker.read_bytes(), before)

    def test_concurrent_policy_change_is_not_undone(self):
        state.watchdog_pause(self.backup)
        self.units[SERVICE]['UnitFileState'] = 'masked'
        with self.assertRaisesRegex(RuntimeError, 'policy changed'):
            state.watchdog_resume()
        self.assertTrue(self.marker.exists())
        self.assertFalse(any(c[0] == 'start' for c in self.changes()))

    def test_manual_stop_intent_is_respected(self):
        state.watchdog_pause(self.backup)
        exists = Path.exists
        def inhibited(path):
            return str(path) == '/run/x-manager/service-control/stopped/'+SERVICE or exists(path)
        with patch.object(Path, 'exists', inhibited):
            with self.assertRaisesRegex(RuntimeError, 'manually inhibited'):
                state.watchdog_resume()
        self.assertFalse(any(c[0] == 'start' for c in self.changes()))

    def test_transition_is_read_only_failure(self):
        self.units[SERVICE]['ActiveState'] = 'activating'
        with self.assertRaisesRegex(RuntimeError, 'stable external watcher'):
            state.watchdog_preflight()
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.changes(), [])

    def test_backup_precedes_stop(self):
        (self.backup/'files.tar').unlink()
        with self.assertRaisesRegex(RuntimeError, 'Complete backup'):
            state.watchdog_pause(self.backup)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.changes(), [])

    def test_rollback_does_not_restore_historical_watchdog_state(self):
        historical = {'services': {SERVICE: {'active': True, 'enabled': 'disabled'},
                                   TIMER: {'active': True, 'enabled': 'disabled'}},
                      'paths': [], 'databases': []}
        (self.backup/'state.json').write_text(json.dumps(historical))
        self.units[SERVICE]['ActiveState'] = 'inactive'
        state.watchdog_pause(self.backup)
        with patch.object(state, 'SERVICES', [SERVICE, TIMER]), patch.object(state, 'save_watcher_policy', return_value=({}, {})), patch.object(state, 'restore_watcher_policy'):
            state.restore(self.backup)
        self.assertEqual(self.changes(), [['stop', TIMER]])
        state.watchdog_resume()
        self.assertEqual(self.changes(), [['stop', TIMER], ['start', TIMER]])

    def test_historical_policy_restore_preserves_current_stop_off_and_guards(self):
        policy = self.root/'etc/x-manager/service-control/state.json'
        policy.parent.mkdir(parents=True)
        intent = {'off': True, 'autostart': False}
        policy.write_text(json.dumps({'version': 1, 'units': {SERVICE: intent}}))
        files = state.watcher_policy_files(self.root)
        for path in files[:3]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('current guard')
            path.chmod(0o600)
        saved = state.save_watcher_policy(self.root)
        policy.write_text(json.dumps({'version': 1, 'units': {SERVICE: {'off': False}, TIMER: {'off': False}, 'snell.service': {'off': True}}}))
        for path in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('historical guard')
        state.restore_watcher_policy(saved, self.root)
        restored = json.loads(policy.read_text())['units']
        self.assertEqual(restored[SERVICE], intent)
        self.assertNotIn(TIMER, restored)
        self.assertEqual(restored['snell.service'], {'off': True})
        self.assertTrue(all(path.read_text() == 'current guard' for path in files[:3]))
        self.assertTrue(all(not path.exists() for path in files[3:]))


class ExitTrapMaintenance(unittest.TestCase):
    def exercise(self, failure=False, rollback=False, restore_failure=False, pause_failure=False, rollback_failure=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'scripts').mkdir()
            (root/'backup').mkdir()
            helper = '''import os, pathlib, sys
root = pathlib.Path(os.environ['FIXTURE'])
mode = sys.argv[1]
with (root/'calls').open('a') as out: out.write(mode+'\\n')
if mode == 'watchdog-resume' and os.environ.get('RESTORE_FAILURE') == 'yes': sys.exit(9)
if mode == 'watchdog-pause' and os.environ.get('PAUSE_FAILURE') == 'yes': sys.exit(8)
if mode == 'restore' and os.environ.get('ROLLBACK_FAILURE') == 'yes': sys.exit(6)
'''
            (root/'scripts/installer-state.py').write_text(helper)
            script = '''set -eE
source "$COMMON"
SCRIPT_DIR="$FIXTURE"
mktemp() { printf '%s\\n' "$FIXTURE/backup"; }
xm_begin
if [ "$ROLLBACK" = yes ]; then python3 "$XM_BACKUP/installer-state.py" restore "$FIXTURE/old"; fi
if [ "$FAILURE" = yes ]; then exit 7; fi
xm_finish
'''
            result = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                env=dict(os.environ, COMMON=str(ROOT/'scripts/installer-common.sh'), FIXTURE=temporary,
                         FAILURE='yes' if failure else 'no', ROLLBACK='yes' if rollback else 'no',
                         RESTORE_FAILURE='yes' if restore_failure else 'no', PAUSE_FAILURE='yes' if pause_failure else 'no',
                         ROLLBACK_FAILURE='yes' if rollback_failure else 'no'))
            return result, (root/'calls').read_text().splitlines()

    def test_failure_rolls_back_before_resume(self):
        result, calls = self.exercise(failure=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(calls, ['backup', 'watchdog-pause', 'restore', 'watchdog-resume'])

    def test_success_and_explicit_rollback_resume(self):
        for rollback in (False, True):
            result, calls = self.exercise(rollback=rollback)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, ['backup', 'watchdog-pause'] + (['restore'] if rollback else []) + ['watchdog-resume'])

    def test_partial_pause_does_not_restore_managed_files(self):
        result, calls = self.exercise(pause_failure=True)
        self.assertEqual(result.returncode, 8)
        self.assertEqual(calls, ['backup', 'watchdog-pause', 'watchdog-resume'])

    def test_resume_failure_is_nonzero_with_recovery_instruction(self):
        result, calls = self.exercise(restore_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--recover-watchdog', result.stderr)
        self.assertNotIn('restore', calls)

    def test_failed_rollback_keeps_watchdog_paused_for_recovery(self):
        result, calls = self.exercise(failure=True, rollback_failure=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(calls, ['backup', 'watchdog-pause', 'restore'])
        self.assertIn('--recover-watchdog', result.stderr)


if __name__ == '__main__':
    unittest.main()
