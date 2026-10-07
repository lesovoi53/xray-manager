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
