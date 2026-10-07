"""Automatic crash policies preserve intent and roll back as one transaction."""
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('watchdog_defaults', Path(__file__).resolve().parents[1]/'scripts/tuna-watchdog.py')
watchdog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(watchdog)


class Controller:
    def __init__(self):
        self.off = set()
        self.stopped = set()
        self.pollers = []
        self.locks = 0

    def conflicts(self):
        return self.pollers

    def status(self, unit):
        return {'off': unit in self.off, 'stopped': unit in self.stopped}

    @contextlib.contextmanager
    def lock(self):
        self.locks += 1
        yield


class Defaults(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.units = self.root/'units'
        self.units.mkdir()
        self.backups = self.root/'backups'
        self.backups.mkdir()
        self.endpoints = self.root/'endpoints'
        self.controller = Controller()
        self.states = {}
        self.commands = []
        self.failure = None
        self.reloaded = False
        for attribute, value in [('ROOT', self.units), ('BACKUPS', self.backups), ('ENDPOINTS', self.endpoints),
                                 ('UNITS', ['snell', 'mita', 'xray', 'x-ui', 'snell6@1', 'snell6@2'])]:
            mock = patch.object(watchdog, attribute, value)
            mock.start()
            self.addCleanup(mock.stop)
        for attribute, value in [('lifecycle', lambda: self.controller), ('show', self.show), ('ctl', self.ctl)]:
            mock = patch.object(watchdog, attribute, side_effect=value)
            mock.start()
            self.addCleanup(mock.stop)

    def show(self, unit):
        state = dict(LoadState='loaded', ActiveState='inactive', UnitFileState='disabled', Type='simple',
                     Restart='always', RestartUSec='1s', StartLimitBurst='5', StartLimitIntervalUSec='10s')
        state.update(self.states.get(unit, {}))
        path = self.path(unit)
        if self.reloaded and path.exists():
            data = path.read_text()
            state.update(Restart='on-failure' if 'Restart=on-failure' in data else 'no',
                         RestartUSec=data.split('RestartSec=')[1].strip(),
                         StartLimitBurst=data.split('StartLimitBurst=')[1].splitlines()[0],
                         StartLimitIntervalUSec='infinity')
            if self.failure == unit:
                state['RestartUSec'] = '60s'
        return state

    def ctl(self, *args):
        self.commands.append(args)
        self.assertEqual(args, ('daemon-reload',), 'No lifecycle/counter mutations permitted')
        self.reloaded = True
        return ''

    def path(self, unit):
        return self.units/(unit+'.service.d')/watchdog.NAME

    def file(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)

    def test_defaults_inactive_manual_stop_xray_and_xui_without_activation_idempotent(self):
        self.controller.stopped.add('snell')
        self.file(self.endpoints/'1'/'endpoint.json', '{}')
        first = watchdog.defaults()
        self.assertEqual(first['changed'], ['snell', 'mita', 'xray', 'x-ui', 'snell6@1'])
        self.assertIn({'unit': 'snell6@2', 'reason': 'no-endpoint'}, first['skipped'])
        self.assertIn('StartLimitBurst=6', self.path('snell').read_text())
        self.assertIn('RestartSec=30s', self.path('snell').read_text())
        self.assertEqual(self.controller.stopped, {'snell'})
        second = watchdog.defaults()
        self.assertEqual(second['changed'], [])
        self.assertIsNone(second['backup'])
        self.assertEqual(self.commands, [('daemon-reload',)])
        manifest = json.loads((Path(first['backup'])/'state.json').read_text())
        self.assertTrue(all(not record['existed'] for record in manifest['files']))

    def test_off_masked_oneshot_missing_are_preserved(self):
        self.controller.off.add('snell')
        self.states = {'mita': {'LoadState': 'masked'}, 'xray': {'Type': 'oneshot'},
                       'x-ui': {'LoadState': 'not-found'}}
        result = watchdog.defaults()
        self.assertFalse(result['changed'])
        self.assertFalse(list(self.units.iterdir()))
        self.assertFalse(list(self.backups.iterdir()))
        self.assertEqual(self.commands, [])

    def test_custom_restart_own_disabled_and_runtime_template_policies_preserved(self):
        self.file(self.path('snell'), watchdog.render(0, 40))
        self.file(self.path('mita').with_name('99-admin.conf'), '[Service]\nRestart=no\n')
        runtime = self.root/'runtime.conf'
        runtime.write_text('[Unit]\nStartLimitBurst=9\n')
        self.states['xray'] = {'DropInPaths': str(runtime).replace(' ', r'\x20')}
        self.file(self.endpoints/'1'/'endpoint.json', '{}')
        self.file(self.units/'snell6@.service.d'/'10-admin.conf', '[Service]\nRestartSec=60\n')
        result = watchdog.defaults()
        self.assertEqual(result['changed'], ['x-ui'])
        self.assertIn('Restart=no', self.path('snell').read_text())
        self.assertEqual(runtime.read_text(), '[Unit]\nStartLimitBurst=9\n')

    def test_lifecycle_conditions_do_not_prevent_default_policy(self):
        self.file(self.path('snell').with_name('95-tuna-service-control.conf'),
                  '[Unit]\nConditionPathExists=!/run/x-manager/service-control/stopped/snell.service\n')
        self.assertIn('snell', watchdog.defaults()['changed'])

    def test_active_or_stopping_external_watcher_fails_before_files_or_lock(self):
        for state in ({'unit': 'vpn-watchdog.timer', 'conflict': True},
                      {'unit': 'tuna-watchdog.service', 'conflict': False, 'ActiveState': 'deactivating'}):
            self.controller.pollers = [state]
            with self.assertRaisesRegex(ValueError, 'watchdog'):
                watchdog.defaults()
        self.assertEqual(self.controller.locks, 0)
        self.assertFalse(list(self.units.iterdir()))
        self.assertFalse(list(self.backups.iterdir()))
        self.assertEqual(self.commands, [])

    def test_effective_delay_mismatch_rolls_back_all_units_and_keeps_foreign_files(self):
        unrelated = self.path('mita').with_name('10-environment.conf')
        self.file(unrelated, '[Service]\nEnvironment=MODE=test\n')
        self.failure = 'x-ui'
        with self.assertRaisesRegex(ValueError, 'x-ui'):
            watchdog.defaults()
        self.assertFalse(any(self.path(unit).exists() for unit in watchdog.UNITS))
        self.assertEqual(unrelated.read_text(), '[Service]\nEnvironment=MODE=test\n')
        self.assertEqual(list(self.units.iterdir()), [unrelated.parent])
        self.assertEqual(self.commands, [('daemon-reload',), ('daemon-reload',)])

    def test_late_file_write_failure_also_rolls_back_earlier_units(self):
        original = Path.open
        def fail(path, *args, **kwargs):
            if path == self.path('xray') and args and args[0] == 'x':
                raise OSError('injected write failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', fail), self.assertRaisesRegex(OSError, 'injected'):
            watchdog.defaults()
        self.assertFalse(list(self.units.iterdir()))
        self.assertEqual(self.commands, [('daemon-reload',)])


if __name__ == '__main__':
    unittest.main()
