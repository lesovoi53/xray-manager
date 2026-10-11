"""Shared OpenFlux recovery accounting, migration and transactional failures."""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('shared_watchdog', Path(__file__).resolve().parents[1] / 'scripts/openflux-watchdog.py')
wd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wd)


class Controller:
    def __init__(self):
        self.off, self.stopped, self.pollers = set(), set(), []

    def conflicts(self):
        return self.pollers

    def allowed(self, unit):
        return unit not in self.off | self.stopped

    def status(self, unit):
        return {'off': unit in self.off, 'stopped': unit in self.stopped}

    def lock(self):
        return contextlib.nullcontext()


class SharedBudget(unittest.TestCase):
    def test_recovery_start_and_execcondition_spend_exactly_one_attempt(self):
        self.budget.now = lambda: 1000
        self.budget.configure(5, 5)
        unit = wd.UNITS[0]
        self.states[unit] = {'NRestarts': '8', 'Result': 'exec-condition'}
        wd.atomic(self.budget.path(wd.STATE), wd.encoded({
            'version': 1, 'spent': 5, 'receipts': {}, 'exhausted_at': 700, 'pending': [unit]}))
        original = self.command
        self.budget.run = lambda *args: '' if args[1] == 'start' else original(*args)
        self.budget.recover()
        self.assertEqual(self.budget.status()['spent'], 1)
        self.assertTrue(self.budget.gate(unit))
        self.assertEqual(self.budget.status()['spent'], 1)
        self.states[unit]['InvocationID'] = '2' * 32
        self.assertTrue(self.budget.gate(unit))
        self.assertEqual(self.budget.status()['spent'], 2)

    def test_explicit_start_is_not_blocked_by_external_watcher(self):
        self.budget.configure(5, 5)
        self.controller.pollers = [{'conflict': True}]
        before = self.budget.path(wd.STATE).read_bytes()
        self.assertTrue(self.budget.gate(wd.UNITS[0]))
        self.assertEqual(self.budget.path(wd.STATE).read_bytes(), before)
        self.states[wd.UNITS[0]] = {'NRestarts': '1'}
        with self.assertRaises(ValueError):
            self.budget.gate(wd.UNITS[0])

    def test_failed_recovery_preserves_condition_and_respects_delay(self):
        self.budget.now = lambda: 1000
        self.budget.configure(5, 5)
        unit = wd.UNITS[0]
        self.states[unit] = {'NRestarts': '7', 'Result': 'exec-condition'}
        wd.atomic(self.budget.path(wd.STATE), wd.encoded({
            'version': 1, 'spent': 5, 'receipts': {}, 'exhausted_at': 700, 'pending': [unit]}))
        original, calls = self.command, []
        def run(*args):
            if args[1] == 'reset-failed':
                self.fail('reset-failed would erase the reason for resuming this channel')
            if args[1] == 'start':
                calls.append(args)
                raise RuntimeError('synthetic start failure')
            return original(*args)
        self.budget.run = run
        with self.assertRaises(RuntimeError): self.budget.recover()
        self.assertEqual(self.budget.recover()['status'], 'cooldown')
        self.assertEqual(len(calls), 1)
        self.budget.now = lambda: 1005
        with self.assertRaises(RuntimeError): self.budget.recover()
        self.assertEqual(self.budget.status()['spent'], 2)

    def test_recovery_never_exceeds_shared_budget_with_multiple_waiting_channels(self):
        self.budget.now = lambda: 1000
        self.budget.configure(2, 5)
        waiting = list(wd.UNITS[:3])
        for unit in waiting:
            self.states[unit] = {'NRestarts': '2', 'Result': 'exec-condition'}
        wd.atomic(self.budget.path(wd.STATE), wd.encoded({
            'version': 1, 'spent': 2, 'receipts': {}, 'exhausted_at': 700,
            'pending': waiting,
        }))
        original, calls = self.command, []
        def run(*args):
            if args[1] in ('reset-failed', 'start'):
                calls.append(args)
                return ''
            return original(*args)
        self.budget.run = run
        self.assertEqual(self.budget.recover()['started'], waiting[:2])
        state = self.budget.read(wd.STATE)
        self.assertEqual(state['spent'], 2)
        self.assertEqual(state['pending'], waiting[2:])
        self.assertEqual([row for row in calls if row[1] == 'start'], [
            ('systemctl', 'start', '--no-block', waiting[0]),
            ('systemctl', 'start', '--no-block', waiting[1]),
        ])

    def test_timer_recovers_only_budget_blocked_channels_after_300_seconds(self):
        self.budget.now = lambda: 1000
        self.budget.configure(1, 5)
        self.budget.reserve(wd.UNITS[0], 'used')
        self.states[wd.UNITS[0]] = {'NRestarts': '2', 'Result': 'exec-condition'}
        self.assertFalse(self.budget.gate(wd.UNITS[0]))
        self.budget.now = lambda: 1299
        self.assertEqual(self.budget.recover()['status'], 'cooldown')
        self.budget.now = lambda: 1300
        original = self.command
        starts = []
        def run(*args):
            if args[1] in ('reset-failed', 'start'):
                starts.append(args)
                return ''
            return original(*args)
        self.budget.run = run
        self.assertEqual(self.budget.recover()['started'], [wd.UNITS[0]])
        self.assertEqual(starts[-1], ('systemctl', 'start', '--no-block', wd.UNITS[0]))
        self.assertEqual(self.budget.status()['spent'], 1)
        self.assertEqual(self.budget.recover()['started'], [])

    def test_timer_preserves_manual_stop_and_off_after_exhaustion(self):
        self.budget.now = lambda: 1000
        self.budget.configure(1, 5)
        self.budget.reserve(wd.UNITS[0], 'used')
        for unit in wd.UNITS[:2]:
            self.states[unit] = {'NRestarts': '2', 'Result': 'exec-condition'}
            self.assertFalse(self.budget.gate(unit))
        self.controller.off.add(wd.UNITS[0])
        self.states[wd.UNITS[1]]['Result'] = 'success'
        self.budget.now = lambda: 1300
        self.assertEqual(self.budget.recover()['started'], [])
        self.assertEqual(self.budget.read(wd.STATE)['pending'], [])

    def test_external_watchdog_blocks_recovery_without_resetting_budget(self):
        self.budget.now = lambda: 1000
        self.budget.configure(1, 5)
        self.budget.reserve(wd.UNITS[0], 'used')
        self.states[wd.UNITS[0]] = {'NRestarts': '2', 'Result': 'exec-condition'}
        self.assertFalse(self.budget.gate(wd.UNITS[0]))
        before = self.budget.path(wd.STATE).read_bytes()
        self.budget.now = lambda: 1300
        self.controller.pollers = [{'conflict': True}]
        with self.assertRaises(ValueError):
            self.budget.recover()
        self.assertEqual(self.budget.path(wd.STATE).read_bytes(), before)
        self.assertEqual(self.commands, [('systemctl', 'daemon-reload')])

    def test_failed_recovery_start_spends_one_attempt_and_waits_before_retry(self):
        self.budget.now = lambda: 1000
        self.budget.configure(1, 5)
        unit = wd.UNITS[0]
        self.budget.reserve(unit, 'used')
        self.states[unit] = {'NRestarts': '2', 'Result': 'exec-condition'}
        self.assertFalse(self.budget.gate(unit))
        self.budget.now = lambda: 1300
        original, starts = self.command, []
        def run(*args):
            if args[1] == 'reset-failed':
                return ''
            if args[1] == 'start':
                starts.append(args)
                raise RuntimeError('synthetic start failure')
            return original(*args)
        self.budget.run = run
        with self.assertRaisesRegex(RuntimeError, 'synthetic start failure'):
            self.budget.recover()
        state = self.budget.read(wd.STATE)
        self.assertEqual(state['spent'], 1)
        self.assertEqual(state['pending'], [unit])
        self.assertEqual(self.budget.recover()['status'], 'cooldown')
        self.assertEqual(len(starts), 1)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.controller = Controller()
        self.states, self.commands = {}, []
        self.failure = None
        self.budget = wd.Watchdog(self.root, self.command, self.controller)

    def file(self, path, content):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def policy(self, unit):
        return self.budget.path('/etc/systemd/system/' + unit + '.d/' + wd.DROPIN)

    def command(self, *args):
        if args == ('systemctl', 'daemon-reload'):
            self.commands.append(args)
            return ''
        self.assertEqual(args[:2], ('systemctl', 'show'), 'No start/stop/reset commands allowed')
        unit = args[2]
        state = dict(LoadState='loaded', Type='simple', ActiveState='inactive', UnitFileState='disabled',
                     DropInPaths='', NRestarts='0', InvocationID='1' * 32)
        state.update(self.states.get(unit, {}))
        path = self.policy(unit)
        if path.exists() and 'RestartSec=' in path.read_text():
            data = path.read_text()
            state.update(Restart='on-failure' if 'Restart=on-failure' in data else 'no',
                         RestartUSec=data.split('RestartSec=')[1].splitlines()[0],
                         StartLimitIntervalUSec='0', ExecCondition=wd.HOOK)
            if unit in self.controller.off:
                state['Restart'] = 'no'
            if unit == self.failure:
                state['RestartUSec'] = '900s'
        return '\n'.join(key + '=' + value for key, value in state.items())

    def test_all_eight_share_exact_limit_receipts_and_persistent_reopen(self):
        self.assertEqual(self.budget.configure(3, 10)['changed'], list(wd.UNITS))
        self.assertTrue(self.budget.reserve(wd.UNITS[0], 'one'))
        self.assertTrue(self.budget.reserve(wd.UNITS[0], 'one'))
        self.assertTrue(self.budget.reserve(wd.UNITS[1], 'two'))
        self.assertTrue(self.budget.reserve(wd.UNITS[7], 'three'))
        self.assertFalse(self.budget.reserve(wd.UNITS[2], 'four'))
        reopened = wd.Watchdog(self.root, self.command, self.controller)
        self.assertEqual(reopened.status()['spent'], 3)
        self.assertEqual(reopened.status()['remaining'], 0)
        self.assertTrue(reopened.status()['exhausted'])

    @unittest.skipUnless(os.name == 'posix', 'Production flock requires POSIX')
    def test_concurrent_reservations_cannot_exceed_group_limit(self):
        self.budget.configure(3, 10)
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda unit: self.budget.reserve(unit), wd.UNITS))
        self.assertEqual(sum(outcomes), 3)
        self.assertEqual(self.budget.status()['spent'], 3)

    def test_initial_manual_gate_free_automatic_gate_idempotent(self):
        self.budget.configure(1, 10)
        self.assertTrue(self.budget.gate(wd.UNITS[0]))
        self.assertEqual(self.budget.status()['spent'], 0)
        self.states[wd.UNITS[0]] = {'NRestarts': '1'}
        self.assertTrue(self.budget.gate(wd.UNITS[0]))
        self.assertTrue(self.budget.gate(wd.UNITS[0]))
        self.states[wd.UNITS[0]]['InvocationID'] = '2' * 32
        self.assertFalse(self.budget.gate(wd.UNITS[0]))
        self.assertEqual(self.budget.status()['spent'], 1)
        self.states[wd.UNITS[0]] = {'NRestarts': '0', 'InvocationID': ''}
        self.assertFalse(self.budget.gate(wd.UNITS[0]))

    def test_configuration_repeated_or_changed_does_not_refill(self):
        self.budget.configure(3, 10)
        self.budget.reserve(wd.UNITS[0])
        state = self.budget.path(wd.STATE).read_bytes()
        self.assertEqual(self.budget.configure(3, 10)['changed'], [])
        self.budget.configure(4, 20)
        self.assertEqual(self.budget.path(wd.STATE).read_bytes(), state)
        self.assertEqual(self.budget.status()['spent'], 1)
        self.budget.configure(0, 10)
        self.assertFalse(self.budget.reserve(wd.UNITS[1]))
        self.assertEqual(self.budget.status()['spent'], 1)

    def test_reset_only_counter_no_lifecycle(self):
        self.budget.configure(3, 10)
        self.budget.reserve(wd.UNITS[0])
        commands = list(self.commands)
        config = self.budget.path(wd.CONFIG).read_bytes()
        self.assertEqual(self.budget.reset()['spent'], 0)
        self.assertEqual(self.commands, commands)
        self.assertEqual(self.budget.path(wd.CONFIG).read_bytes(), config)

    def test_existing_native_counts_migrate_conservatively_and_old_files_backed_up(self):
        old_data = ('# Managed by TUNA watchdog; reset limit explicitly from the menu.\n[Unit]\n'
                    'StartLimitIntervalSec=infinity\nStartLimitBurst=4\n[Service]\nRestart=on-failure\nRestartSec=10s\n')
        old = self.policy(wd.UNITS[0]).with_name(wd.OLD_DROPIN)
        self.file(old, old_data)
        self.states[wd.UNITS[0]] = {'NRestarts': '2'}
        self.states[wd.UNITS[1]] = {'NRestarts': '1'}
        result = self.budget.configure(3, 10)
        self.assertFalse(old.exists())
        self.assertEqual(self.budget.status()['spent'], 3)
        backup = Path(result['backup'])
        records = json.loads((backup / 'state.json').read_text())['files']
        record = next(row for row in records if row['path'] == str(old))
        self.assertEqual((backup / record['copy']).read_text(), old_data)

    def test_off_and_stop_intent_untouched_and_never_reserved(self):
        self.controller.off.add(wd.UNITS[0])
        self.controller.stopped.add(wd.UNITS[1])
        marker = self.root / 'etc/x-manager/service-control/off' / wd.UNITS[0]
        self.file(marker, 'preserve')
        self.budget.configure(3, 10)
        for unit in wd.UNITS[:2]:
            self.assertFalse(self.budget.reserve(unit))
            self.assertFalse(self.budget.gate(unit))
        self.assertEqual(marker.read_text(), 'preserve')
        self.assertEqual(self.budget.status()['spent'], 0)

    def test_foreign_restart_or_condition_override_refused_without_writes(self):
        for directive in ('Restart=no', 'StartLimitBurst=100', 'ExecCondition='):
            foreign = self.policy(wd.UNITS[4]).with_name('99-admin.conf')
            self.file(foreign, '[Service]\n' + directive + '\n')
            with self.assertRaises(ValueError):
                self.budget.configure(3, 10)
            self.assertFalse(self.budget.path(wd.CONFIG).exists())
            self.assertFalse(any(self.policy(unit).exists() for unit in wd.UNITS))
            self.assertEqual(foreign.read_text(), '[Service]\n' + directive + '\n')
            foreign.unlink()

    def test_foreign_contents_at_owned_names_are_refused(self):
        for name in (wd.DROPIN, wd.OLD_DROPIN):
            path = self.policy(wd.UNITS[0]).with_name(name)
            self.file(path, '[Service]\nRestart=no\n')
            with self.assertRaises(ValueError):
                self.budget.configure(3, 10)
            self.assertEqual(path.read_text(), '[Service]\nRestart=no\n')
            path.unlink()

    def test_failed_effective_verification_rolls_back_every_policy_and_config(self):
        self.budget.configure(3, 10)
        self.budget.reserve(wd.UNITS[0])
        paths = [self.policy(unit) for unit in wd.UNITS] + [self.budget.path(wd.CONFIG), self.budget.path(wd.STATE)]
        before = {path: path.read_bytes() for path in paths}
        self.failure = wd.UNITS[4]
        with self.assertRaises(ValueError):
            self.budget.configure(10, 20)
        self.assertEqual({path: path.read_bytes() for path in paths}, before)

    def test_first_install_failure_removes_partial_configuration(self):
        self.failure = wd.UNITS[4]
        with self.assertRaises(ValueError):
            self.budget.configure(3, 10)
        self.assertFalse(self.budget.path(wd.CONFIG).exists())
        self.assertFalse(self.budget.path(wd.STATE).exists())
        self.assertFalse(any(self.policy(unit).exists() for unit in wd.UNITS))

    def test_missing_corrupt_state_fail_closed_do_not_refill(self):
        self.budget.configure(3, 10)
        path = self.budget.path(wd.STATE)
        for data in (None, '{broken', '{"version":1,"spent":-1,"receipts":{}}'):
            if data is None:
                path.unlink()
            else:
                self.file(path, data)
            for action in (self.budget.configure, lambda: self.budget.reserve(wd.UNITS[0]),
                           lambda: self.budget.gate(wd.UNITS[0])):
                with self.assertRaises((ValueError, OSError)):
                    action()
        self.assertEqual(self.budget.reset()['spent'], 0)

    def test_external_watchdog_blocks_before_any_policy_mutation(self):
        self.controller.pollers = [{'conflict': True}]
        with self.assertRaises(ValueError):
            self.budget.configure(3, 10)
        self.assertFalse(self.budget.path(wd.CONFIG).exists())
        self.assertFalse(self.budget.path(wd.LOCK).exists())

    def test_no_installed_openflux_no_configuration_or_hooks(self):
        self.states = {unit: {'LoadState': 'not-found'} for unit in wd.UNITS}
        self.assertEqual(self.budget.configure(3, 10)['changed'], [])
        self.assertFalse(self.budget.path(wd.CONFIG).exists())
        self.assertFalse(any(self.policy(unit).exists() for unit in wd.UNITS))

    def test_symlink_state_refused(self):
        self.budget.configure(3, 10)
        path = self.budget.path(wd.STATE)
        target = path.with_name('original.json')
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError:
            self.skipTest('symlinks unavailable')
        with self.assertRaises(ValueError):
            self.budget.reserve(wd.UNITS[0])


if __name__ == '__main__':
    unittest.main()
