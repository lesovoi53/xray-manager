"""All reboot commands are captured by a fake systemd boundary, never executed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reboot_schedule', ROOT/'scripts/reboot-schedule.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RebootSchedule(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.fail = None
        self.timer = {'LoadState': 'not-found', 'ActiveState': 'inactive', 'UnitFileState': '',
                      'LastTriggerUSecMonotonic': '95000000', 'NextElapseUSecRealtime': 'tomorrow'}
        self.foreign = False
        self.scheduler = mod.Scheduler(self.root, self.command)

    def command(self, *args):
        self.calls.append(args)
        if args[0] == 'systemd-analyze':
            return 'valid calendar'
        if args[:2] == ('systemctl', 'show'):
            if args[2] == mod.TIMER:
                values = self.timer
            elif args[2] == mod.SERVICE:
                values = {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': '999'}
            else:
                values = {'LoadState': 'loaded' if self.foreign else 'not-found',
                          'ActiveState': 'active' if self.foreign else 'inactive', 'UnitFileState': ''}
            return '\n'.join(key+'='+value for key, value in values.items())
        if self.fail == args[1]:
            self.fail = None
            raise RuntimeError('synthetic systemctl failure')
        if args[1] == 'daemon-reload':
            if self.scheduler.path(mod.TIMER_FILE).exists():
                self.timer['LoadState'] = 'loaded'
                self.timer['UnitFileState'] = self.timer['UnitFileState'] or 'disabled'
            else:
                self.timer.update(LoadState='not-found', ActiveState='inactive', UnitFileState='')
        elif args[1] == 'enable':
            self.timer['UnitFileState'] = 'enabled-runtime' if '--runtime' in args else 'enabled'
        elif args[1] == 'disable':
            self.timer['UnitFileState'] = 'disabled'
        elif args[1] in ('restart', 'start'):
            self.timer['ActiveState'] = 'active'
        elif args[1] == 'stop':
            self.timer['ActiveState'] = 'inactive'
        elif args[1] != 'reboot':
            raise AssertionError(args)
        return ''

    def configure(self):
        return self.scheduler.configure('04:30', 'Europe/Moscow')

    def run_due(self, **kwargs):
        return self.scheduler.run_due(environment={'INVOCATION_ID': 'a'*32}, now=100, pid=999, **kwargs)

    def assert_no_reboot(self):
        self.assertNotIn(('systemctl', 'reboot'), self.calls)

    def test_bootstrap_is_disabled_without_inventing_schedule_or_timer(self):
        self.scheduler.bootstrap()
        self.assertEqual(self.scheduler.read(), {'version': 1, 'enabled': False, 'time': None, 'timezone': None})
        self.assertFalse(self.scheduler.path(mod.TIMER_FILE).exists())
        self.assertTrue(all(call[1] == 'show' for call in self.calls))
        self.assert_no_reboot()

    def test_existing_disabled_configuration_and_autostart_are_preserved_on_bootstrap(self):
        self.configure()
        self.scheduler.configure(enabled=False)
        before = self.scheduler.path(mod.CONFIG).read_bytes()
        self.calls.clear()
        self.assertFalse(self.scheduler.bootstrap()['changed'])
        self.assertEqual(self.scheduler.path(mod.CONFIG).read_bytes(), before)
        self.assertEqual(self.timer['UnitFileState'], 'disabled')
        self.assertEqual(self.calls, [])

    def test_configure_validates_and_never_reboots(self):
        result = self.configure()
        self.assertTrue(Path(result['backup'], 'state.json').exists())
        unit = self.scheduler.path(mod.TIMER_FILE).read_text()
        self.assertIn('OnCalendar=*-*-* 04:30:00 Europe/Moscow', unit)
        self.assertIn('Persistent=false', unit)
        self.assertIn('RandomizedDelaySec=600', unit)
        self.assertEqual(self.timer['UnitFileState'], 'enabled')
        self.assert_no_reboot()

    def test_malformed_time_or_timezone_cannot_write_schedule(self):
        for schedule_time, timezone in [('4:30', 'UTC'), ('24:00', 'UTC'), ('12:60', 'UTC'),
                                        ('04:30', 'Not/A_Zone'), ('04:30', '../etc/passwd')]:
            with self.subTest(time=schedule_time, zone=timezone), self.assertRaises(ValueError):
                self.scheduler.configure(schedule_time, timezone)
            self.assertFalse(self.scheduler.path(mod.CONFIG).exists())
        self.assert_no_reboot()

    def test_foreign_schedule_is_reported_and_not_modified(self):
        self.foreign = True
        with self.assertRaisesRegex(RuntimeError, 'Foreign reboot schedule'):
            self.configure()
        self.assertFalse(self.scheduler.path(mod.CONFIG).exists())
        self.assertTrue(all(c[1] in ('show', 'calendar') for c in self.calls))
        self.assert_no_reboot()

    def test_admin_timer_and_mask_are_not_overwritten(self):
        timer = self.scheduler.path(mod.TIMER_FILE)
        timer.parent.mkdir(parents=True)
        timer.write_text('[Timer]\nOnCalendar=daily\n')
        self.timer.update(LoadState='loaded', UnitFileState='disabled')
        with self.assertRaisesRegex(RuntimeError, 'Foreign reboot timer'):
            self.configure()
        self.assertEqual(timer.read_text(), '[Timer]\nOnCalendar=daily\n')
        self.timer.update(LoadState='masked', UnitFileState='masked')
        with self.assertRaisesRegex(RuntimeError, 'masked'):
            self.configure()
        self.assert_no_reboot()

    def test_configure_failure_restores_files_and_previous_timer_state(self):
        self.configure()
        self.scheduler.configure(enabled=False)
        config = self.scheduler.path(mod.CONFIG).read_bytes()
        unit = self.scheduler.path(mod.TIMER_FILE).read_bytes()
        self.fail = 'restart'
        with self.assertRaisesRegex(RuntimeError, 'original state restored'):
            self.scheduler.configure('05:15', 'UTC')
        self.assertEqual(self.scheduler.path(mod.CONFIG).read_bytes(), config)
        self.assertEqual(self.scheduler.path(mod.TIMER_FILE).read_bytes(), unit)
        self.assertEqual(self.timer['ActiveState'], 'inactive')
        self.assertEqual(self.timer['UnitFileState'], 'disabled')
        self.assert_no_reboot()

    def test_first_setup_failure_removes_created_timer_and_config(self):
        self.fail = 'restart'
        with self.assertRaisesRegex(RuntimeError, 'original state restored'):
            self.configure()
        self.assertFalse(self.scheduler.path(mod.CONFIG).exists())
        self.assertFalse(self.scheduler.path(mod.TIMER_FILE).exists())
        self.assertEqual(self.timer['LoadState'], 'not-found')
        self.assert_no_reboot()

    def test_runtime_enablement_remains_runtime_after_schedule_change(self):
        self.configure()
        self.timer['UnitFileState'] = 'enabled-runtime'
        self.scheduler.configure('05:00', 'UTC')
        self.assertEqual(self.timer['UnitFileState'], 'enabled-runtime')
        self.assert_no_reboot()

    def test_install_and_schedule_lock_contention_skip_without_queue(self):
        self.configure()
        for lock in (mod.INSTALL_LOCK, mod.LOCK):
            with self.subTest(lock=lock), self.scheduler.lock(lock) as acquired:
                self.assertTrue(acquired)
                self.assertFalse(self.run_due()['reboot'])
        self.assert_no_reboot()

    def test_maintenance_marker_disabled_and_manual_invocations_skip(self):
        self.configure()
        marker = self.scheduler.path(mod.MAINTENANCE)
        marker.parent.mkdir(parents=True)
        marker.write_text('{}')
        self.assertFalse(self.run_due()['reboot'])
        marker.unlink()
        self.assertFalse(self.scheduler.run_due(environment={})['reboot'])
        self.scheduler.configure(enabled=False)
        self.assertFalse(self.run_due()['reboot'])
        self.assert_no_reboot()

    def test_late_timer_event_is_skipped(self):
        self.configure()
        self.timer['LastTriggerUSecMonotonic'] = '1000000'
        self.assertFalse(self.run_due()['reboot'])
        self.assert_no_reboot()

    def test_only_actual_enabled_current_timer_requests_mock_reboot(self):
        self.configure()
        self.assertTrue(self.run_due()['reboot'])
        self.assertEqual(self.calls.count(('systemctl', 'reboot')), 1)

    def test_service_unit_has_no_direct_reboot_command(self):
        service = (ROOT/'systemd/x-manager-reboot.service').read_text()
        self.assertIn('/scripts/reboot-schedule.py run', service)
        self.assertNotIn('ExecStart=/usr/bin/systemctl reboot', service)


if __name__ == '__main__':
    unittest.main()
