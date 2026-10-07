"""Lifecycle contract using a disposable filesystem and the system command seam.

These are intent/failure-path tests; Debian systemd acceptance is separate.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "service-control.py"
SPEC = importlib.util.spec_from_file_location("service_control", SCRIPT)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class Systemd:
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.units = {u: {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled",
                          "Type": "simple", "Restart": "always", "Result": "success"}
                      for u in control.UNITS}
        # Legacy installation: v5 is running; optional v6 slots are dormant.
        for unit, state in self.units.items():
            if unit.startswith("snell6@"):
                state.update(ActiveState="inactive", UnitFileState="disabled")
        self.fail_action = None
        self.conditions_removed = False
        self.competing_restart = False

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "busctl":
            encoded = args[-3].rsplit("/", 1)[1]
            unit = next(u for u in control.UNITS if "".join(
                c if c.isascii() and c.isalnum() else "_%02x" % ord(c) for c in u) == encoded)
            conditions = [] if self.conditions_removed else [
                ["ConditionPathExists", False, True, control.STATE_DIR + "/off/" + unit, 0],
                ["ConditionPathExists", False, True, control.RUNTIME_DIR + "/stopped/" + unit, 0]]
            return json.dumps({"type": "a(sbbsi)", "data": conditions})
        action = args[1]
        if action == self.fail_action:
            raise RuntimeError("injected " + action + " failure")
        if action == "daemon-reload":
            for unit, live in self.units.items():
                dropin = self.root / "etc/systemd/system" / (unit + ".d") / control.DROPIN
                off = dropin.exists() and "Restart=no" in dropin.read_text()
                live["Restart"] = "no" if off and not self.competing_restart else "always"
            return ""
        unit = args[2]
        live = self.units[unit]
        if action == "show":
            return "\n".join(key + "=" + value for key, value in live.items())
        if action == "disable":
            live["UnitFileState"] = "disabled"
        elif action == "enable":
            live["UnitFileState"] = "enabled"
        elif action == "stop":
            live["ActiveState"] = "inactive"
        elif action in ("start", "restart"):
            blocked = any((self.root / folder.lstrip("/") / unit).exists()
                          for folder in (control.STATE_DIR + "/off", control.RUNTIME_DIR + "/stopped"))
            live["ActiveState"] = "inactive" if blocked else "active"
        return ""


class ServiceControl(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.systemd = Systemd(self.root)
        self.control = control.Controller(self.root, self.systemd)

    def test_permanent_off_preserves_local_unit_and_blocks_external_starts(self):
        local = self.root / "etc/systemd/system/snell.service"
        local.parent.mkdir(parents=True)
        local.write_bytes(b"[Service]\nExecStart=/usr/local/bin/snell-server\n")
        original = local.read_bytes()
        result = self.control.change("off", "snell")
        self.assertTrue(result["off"])
        self.assertEqual(result["ActiveState"], "inactive")
        self.assertEqual(result["UnitFileState"], "disabled")
        self.assertEqual(local.read_bytes(), original)
        self.assertFalse(any(call[1] in ("mask", "unmask") for call in self.systemd.calls))
        self.systemd("systemctl", "start", "snell.service")
        self.systemd("systemctl", "restart", "snell.service")
        self.assertEqual(self.control.status("snell")["ActiveState"], "inactive")
        self.assertFalse(self.control.allowed("snell"))
        self.assertFalse(self.control.allowed("snell", enable=True))

    def test_off_survives_new_controller_and_installer_reconcile(self):
        self.control.change("off", "openflux@2")
        updated = control.Controller(self.root, self.systemd)
        updated.reconcile()
        self.assertFalse(updated.allowed("openflux@2"))
        self.assertTrue(updated.allowed("openflux@1"))
        self.assertTrue(updated.status("openflux@2")["off"])
        self.assertEqual(updated.status("openflux@1")["ActiveState"], "active")

    def test_start_cannot_clear_permanent_off_or_enable_autostart(self):
        self.control.change("off", "snell")
        for action in ("start", "restart", "autostart-on"):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "постоянно"):
                self.control.change(action, "snell")
        self.assertTrue(self.control.status("snell")["off"])

    def test_on_reverses_only_owned_inhibit_and_restores_start(self):
        foreign = self.root / "etc/systemd/system/snell.service.d/50-user.conf"
        foreign.parent.mkdir(parents=True)
        foreign.write_text("[Service]\nLimitNOFILE=10000\n")
        self.control.change("off", "snell")
        result = self.control.change("on", "snell")
        self.assertFalse(result["off"])
        self.assertEqual(result["ActiveState"], "active")
        self.assertEqual(result["UnitFileState"], "enabled")
        self.assertEqual(result["Restart"], "always")
        self.assertEqual(foreign.read_text(), "[Service]\nLimitNOFILE=10000\n")

    def test_manual_stop_blocks_automation_until_explicit_start(self):
        self.control.change("stop", "mita")
        self.control.reconcile()
        self.assertFalse(self.control.allowed("mita"))
        self.assertEqual(self.control.status("mita")["UnitFileState"], "enabled")
        self.systemd("systemctl", "restart", "mita.service")
        self.assertEqual(self.control.status("mita")["ActiveState"], "inactive")
        self.control.change("start", "mita")
        self.assertTrue(self.control.allowed("mita"))
        self.assertEqual(self.control.status("mita")["ActiveState"], "active")

    def test_boot_clears_runtime_stop_but_retains_persistent_off(self):
        self.control.change("stop", "mita")
        self.control.change("off", "snell")
        # /run is tmpfs: model only our runtime marker disappearing on reboot.
        self.control.markers("mita.service")[1].unlink()
        rebooted = control.Controller(self.root, self.systemd)
        rebooted.reconcile()
        self.assertTrue(rebooted.allowed("mita"))
        self.assertFalse(rebooted.allowed("snell"))

    def test_autostart_off_does_not_stop_and_allows_manual_start(self):
        self.control.change("autostart-off", "snell")
        self.assertEqual(self.control.status("snell")["ActiveState"], "active")
        self.assertFalse(self.control.allowed("snell", enable=True))
        self.assertTrue(self.control.allowed("snell"))
        self.control.change("stop", "snell")
        result = self.control.change("start", "snell")
        self.assertEqual(result["UnitFileState"], "disabled")
        self.assertEqual(result["ActiveState"], "active")
        self.control.reconcile()
        self.assertEqual(self.control.status("snell")["UnitFileState"], "disabled")

    def test_new_units_allowed_but_unknown_or_template_units_rejected(self):
        self.assertTrue(self.control.allowed("openflux@8"))
        for unit in ("sshd", "postgresql", "openflux@9", "openflux@", "../snell", "snell;reboot"):
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                self.control.change("off", unit)
        self.assertFalse(self.systemd.calls)

    def test_existing_administrator_mask_is_never_removed(self):
        self.systemd.units["snell.service"].update(LoadState="masked", UnitFileState="masked")
        for action in ("on", "start", "restart", "autostart-on"):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "mask preserved"):
                self.control.change(action, "snell")
        self.assertFalse(any(call[1] == "unmask" for call in self.systemd.calls))

    def test_off_partial_systemd_failure_retains_inhibit_for_retry(self):
        self.systemd.fail_action = "disable"
        with self.assertRaisesRegex(RuntimeError, "injected disable"):
            self.control.change("off", "snell")
        self.assertFalse(self.control.allowed("snell"))
        self.assertEqual(self.control.status("snell")["ActiveState"], "inactive")
        self.systemd.fail_action = None
        self.control.reconcile()
        self.assertEqual(self.control.status("snell")["UnitFileState"], "disabled")

    def test_foreign_override_preserved_without_any_lifecycle_write(self):
        foreign = self.control.dropin("snell.service")
        foreign.parent.mkdir(parents=True)
        foreign.write_text("# administrator policy\n")
        with self.assertRaisesRegex(ValueError, "foreign contents"):
            self.control.change("off", "snell")
        self.assertEqual(foreign.read_text(), "# administrator policy\n")
        self.assertFalse(self.control.state_path.exists())

    def test_corrupt_state_fails_closed(self):
        self.control.state_path.parent.mkdir(parents=True)
        self.control.state_path.write_text('{"version":2,"units":{}}')
        with self.assertRaisesRegex(ValueError, "Invalid lifecycle"):
            self.control.allowed("snell")
        self.assertFalse(self.systemd.calls)

    def test_condition_reset_detected_and_cannot_unblock_existing_off(self):
        self.control.change("off", "snell")
        self.systemd.conditions_removed = True
        with self.assertRaisesRegex(ValueError, "removed lifecycle guard"):
            self.control.change("on", "snell")
        self.assertFalse(self.control.allowed("snell"))
        self.assertEqual(self.control.status("snell")["ActiveState"], "inactive")

    def test_competing_restart_override_reported_without_reviving_unit(self):
        self.systemd.competing_restart = True
        with self.assertRaisesRegex(ValueError, "supersedes Restart=no"):
            self.control.change("off", "snell")
        self.assertFalse(self.control.allowed("snell"))
        self.assertEqual(self.control.status("snell")["ActiveState"], "inactive")

    def test_timer_inhibit_uses_unit_guard_without_service_directives(self):
        self.control.change("off", "volga-cookies.timer")
        data = self.control.dropin("volga-cookies.timer").read_text()
        self.assertNotIn("[Service]", data)
        self.assertIn("ConditionPathExists=!/etc/x-manager/service-control/off/volga-cookies.timer", data)
        self.assertTrue(self.control.allowed("volga-cookies.service"))

    def test_conflict_report_is_read_only_and_external_units_need_explicit_choice(self):
        self.control.reconcile()
        self.assertFalse(self.systemd.calls)
        conflicts = self.control.conflicts()
        self.assertEqual({s["unit"] for s in conflicts}, set(control.EXTERNAL_WATCHDOGS))
        self.assertTrue(all(s["conflict"] for s in conflicts))
        self.assertTrue(all(call[1] == "show" for call in self.systemd.calls))
        self.control.change("off", "vpn-watchdog")
        self.assertFalse(self.control.status("tuna-watchdog")["off"])
        self.assertEqual(self.control.status("sing-box")["ActiveState"], "active")


if __name__ == "__main__":
    unittest.main()
