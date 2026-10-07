"""Public lifecycle commands cannot bypass exclusive Snell selection."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("snell_lifecycle_fixture", ROOT / "tests/test_service_control.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
control = fixture.control
ACTIVATE = ("on", "start", "restart", "autostart-on")


class SnellLifecycleSelection(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.systemd = fixture.Systemd(self.root)
        self.controller = control.Controller(self.root, self.systemd)
        self.marker = self.root / "etc/x-manager/snell-active.json"

    def select(self, version, slot=None):
        identity = "1" * 32 if version == 6 else None
        unit = "snell6@" + slot + ".service" if version == 6 else "snell.service"
        self.marker.parent.mkdir(parents=True, exist_ok=True)
        self.marker.write_text(json.dumps(dict(format=1, version=version, slot=slot,
                                               unit=unit, endpoint_id=identity)))
        if version == 6:
            self.systemd.units["snell.service"].update(ActiveState="inactive", UnitFileState="disabled")
            endpoint = self.root / "etc/snell6/endpoints" / slot / "endpoint.json"
            endpoint.parent.mkdir(parents=True)
            endpoint.write_text(json.dumps({"endpoint_id": identity}))

    def assert_rejected_without_mutations(self, unit):
        for action in ACTIVATE:
            with self.subTest(action=action, unit=unit):
                self.systemd.calls.clear()
                with self.assertRaises((ValueError, OSError)):
                    self.controller.change(action, unit)
                self.assertTrue(all(call[1] == "show" for call in self.systemd.calls))
                self.assertFalse(self.controller.state_path.exists())
                self.assertFalse(self.controller.dropin(unit).exists())
        self.assertFalse(self.controller.allowed(unit))
        self.assertFalse(self.controller.allowed(unit, enable=True))

    def test_selected_v5_rejects_all_v6_activation_paths(self):
        self.select(5)
        self.assert_rejected_without_mutations("snell6@1.service")

    def test_selected_v6_rejects_v5_and_other_slot(self):
        self.select(6, "2")
        self.assert_rejected_without_mutations("snell.service")
        self.assert_rejected_without_mutations("snell6@1.service")

    def test_selected_endpoint_identity_cannot_be_replaced(self):
        self.select(6, "2")
        endpoint = self.root / "etc/snell6/endpoints/2/endpoint.json"
        endpoint.write_text(json.dumps({"endpoint_id": "2" * 32}))
        self.assert_rejected_without_mutations("snell6@2.service")

    def test_selected_service_can_start_restart_and_enable(self):
        self.select(6, "2")
        for action in ACTIVATE:
            with self.subTest(action=action):
                result = self.controller.change(action, "snell6@2")
                self.assertEqual(result["ActiveState"], "active")
        self.assertTrue(self.controller.allowed("snell6@2"))

    def test_legacy_without_marker_allows_sole_v5(self):
        for action in ACTIVATE:
            with self.subTest(action=action):
                self.controller.change(action, "snell")
        self.assertTrue(self.controller.allowed("snell"))

    def test_legacy_running_or_enabled_opposite_blocks_activation(self):
        for active, enabled in (("active", "disabled"), ("inactive", "enabled"),
                                ("inactive", "enabled-runtime"), ("activating", "disabled")):
            with self.subTest(active=active, enabled=enabled):
                self.systemd.units["snell6@3.service"].update(ActiveState=active, UnitFileState=enabled)
                self.assert_rejected_without_mutations("snell.service")

    def test_legacy_v6_does_not_bypass_running_v5(self):
        self.assert_rejected_without_mutations("snell6@1.service")

    def test_legacy_v6_can_activate_only_when_v5_and_other_slots_are_dormant(self):
        self.systemd.units["snell.service"].update(ActiveState="inactive", UnitFileState="disabled")
        result = self.controller.change("on", "snell6@1")
        self.assertEqual(result["ActiveState"], "active")

    def test_marker_does_not_hide_an_externally_activated_conflict(self):
        self.select(5)
        self.systemd.units["snell6@3.service"].update(ActiveState="active", UnitFileState="disabled")
        self.assert_rejected_without_mutations("snell.service")

    def test_corrupt_selection_blocks_only_activation_and_not_other_services(self):
        self.marker.parent.mkdir(parents=True)
        self.marker.write_text('{"format": 99}')
        self.assert_rejected_without_mutations("snell.service")
        for action in ("off", "stop", "autostart-off"):
            self.controller.change(action, "snell")
        self.controller.change("on", "mita")
        self.assertTrue(self.controller.allowed("mita"))

    def test_inactive_version_can_always_be_disabled(self):
        self.select(6, "2")
        for action in ("stop", "autostart-off", "off"):
            self.controller.change(action, "snell")
        self.assertEqual(self.systemd.units["snell.service"]["ActiveState"], "inactive")
        self.assertEqual(self.systemd.units["snell.service"]["UnitFileState"], "disabled")

    def test_only_explicit_internal_switch_controller_bypasses_selection(self):
        self.select(5)
        self.assertFalse(hasattr(self.controller, "_snell_switch_authorized"))

        class SwitchController(control.Controller):
            _snell_switch_authorized = True

        switching = SwitchController(self.root, self.systemd)
        result = switching.change("on", "snell6@1")
        self.assertEqual(result["ActiveState"], "active")
        self.assert_rejected_after_internal_switch()

    def assert_rejected_after_internal_switch(self):
        with self.assertRaisesRegex(ValueError, "snell-switch"):
            self.controller.change("start", "snell6@1")


if __name__ == "__main__":
    unittest.main()
