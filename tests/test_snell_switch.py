"""Exclusive Snell switching with real lifecycle files and simulated systemd."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location("snell_switch", Path(__file__).resolve().parents[1] / "scripts/snell-switch.py")
switch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(switch)


class System:
    def __init__(self, root):
        self.root, self.calls, self.fail_once = root, [], None
        self.rules = set()
        self.units = {unit: dict(LoadState="loaded", ActiveState="inactive", UnitFileState="disabled",
                                Type="simple", Restart="on-failure", Result="success")
                      for unit in switch.control.UNITS}
        self.units["snell.service"].update(ActiveState="active", UnitFileState="enabled")

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "iptables":
            action, rule = args[2], tuple(args[4:])
            if action == "-C" and rule not in self.rules:
                error = RuntimeError("absent rule")
                error.returncode = 1
                raise error
            if action == "-I":
                self.rules.add(rule)
            elif action == "-D":
                self.rules.remove(rule)
            return ""
        if args[0] == "busctl":
            unit = next(u for u in self.units if "".join(
                c if c.isascii() and c.isalnum() else "_%02x" % ord(c) for c in u) == args[-3].rsplit("/", 1)[1])
            return json.dumps({"data": [["ConditionPathExists", False, True, folder + "/" + unit, 0]
                                       for folder in (switch.control.STATE_DIR + "/off", switch.control.RUNTIME_DIR + "/stopped")]})
        if args[0] != "systemctl":
            return ""
        action = args[1]
        if self.fail_once == action:
            self.fail_once = None
            raise RuntimeError("injected failure")
        if action == "daemon-reload":
            for unit, state in self.units.items():
                dropin = self.root / "etc/systemd/system" / (unit + ".d") / switch.control.DROPIN
                state["Restart"] = "no" if dropin.exists() and "Restart=no" in dropin.read_text() else "on-failure"
            return ""
        unit = args[2] if action == "show" else args[-1]
        state = self.units[unit]
        if action == "show":
            return "\n".join(k + "=" + v for k, v in state.items())
        if action == "stop":
            state["ActiveState"] = "inactive"
        elif action == "enable":
            state["UnitFileState"] = "enabled-runtime" if "--runtime" in args else "enabled"
        elif action == "disable":
            if state["UnitFileState"] not in ("masked", "masked-runtime", "static", "indirect"):
                state["UnitFileState"] = "disabled"
        elif action == "start":
            self.assert_exclusive(unit)
            blocked = any(path.exists() for path in switch.control.Controller(self.root, self).markers(unit))
            state["ActiveState"] = "inactive" if blocked else "active"
        return ""

    def assert_exclusive(self, unit):
        if unit in switch.UNITS and any(u != unit and self.units[u]["ActiveState"] == "active" for u in switch.UNITS):
            raise AssertionError("Attempted simultaneous Snell servers")


class Switching(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system = System(self.root)
        self.probes = []
        self.controller = switch.Controller(self.root, self.system,
                                            lambda value, core, runner: self.probes.append(value["endpoint_id"]))
        self.lifecycle = self.controller.lifecycle
        for name, content in (("etc/snell/snell-server.conf", b"[snell-server]\nlisten=0.0.0.0:1488\npsk=keep\n"),
                              ("usr/local/bin/snell-server", b"legacy-core")):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.endpoint = dict(format=1, endpoint_id="a" * 32, slot="1", version=6, mode="default",
                             name="keep", psk="shared-secret", port=20001, listen="0.0.0.0", routing="direct",
                             socks_port=10808, server_host="192.0.2.1", core_sha256=hashlib.sha256(b"core").hexdigest(),
                             probe_url="https://example.com/", firewall_open=True)
        self.directory = self.root / "etc/snell6/endpoints/1"
        self.directory.mkdir(parents=True)
        endpoint_module = switch.helper("snell6-endpoints")
        (self.directory / "endpoint.json").write_bytes(endpoint_module.encoded(self.endpoint))
        (self.directory / "config.json").write_bytes(endpoint_module.encoded(endpoint_module.render(self.endpoint)))
        (self.directory / "core").write_bytes(b"core")

    def persistent_files(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*")
                if p.is_file() and p.relative_to(self.root).parts[0] not in ("run", "var")}

    def states(self):
        return {unit: dict(self.system.units[unit]) for unit in switch.UNITS}

    def test_switch_both_directions_preserves_configs_and_installs_persistent_inhibits(self):
        configs = {p: p.read_bytes() for p in self.directory.iterdir()}
        v5 = self.root / "etc/snell/snell-server.conf"
        old_v5 = v5.read_bytes()
        result = self.controller.switch(6, "1")
        self.assertTrue(result["changed"])
        self.assertEqual(switch.read_selection(self.root), switch.selection(6, "1", "a" * 32))
        self.assertEqual(self.probes, ["a" * 32])
        self.assertEqual(self.system.units["snell6@1.service"]["ActiveState"], "active")
        for unit in switch.UNITS:
            if unit != "snell6@1.service":
                self.assertTrue(self.lifecycle.status(unit)["off"])
                self.assertFalse(self.lifecycle.allowed(unit, enable=True))
        rebooted = switch.control.Controller(self.root, self.system)
        rebooted.reconcile()
        self.assertFalse(rebooted.allowed("snell.service"))
        self.controller.switch(5)
        self.assertEqual(switch.read_selection(self.root), switch.selection(5))
        self.assertEqual(v5.read_bytes(), old_v5)
        self.assertEqual({p: p.read_bytes() for p in configs}, configs)
        self.assertEqual(self.system.units["snell.service"]["ActiveState"], "active")

    def test_readiness_failure_restores_actual_intents_and_autostart_without_reviving_disabled(self):
        self.lifecycle.change("off", "snell6@3")
        self.lifecycle.change("stop", "snell6@4")
        self.lifecycle.change("autostart-off", "snell")
        before_files, before_states = self.persistent_files(), self.states()
        def fail(*args):
            raise TimeoutError("probe timed out")
        self.controller.probe = fail
        with self.assertRaisesRegex(RuntimeError, "previous lifecycle state restored"):
            self.controller.switch(6, "1")
        self.assertEqual(self.persistent_files(), before_files)
        self.assertEqual(self.states(), before_states)
        self.assertIsNone(switch.read_selection(self.root))
        self.assertTrue(self.lifecycle.status("snell6@4")["stopped"])
        self.assertFalse(self.lifecycle.allowed("snell6@3"))

    def test_partial_lifecycle_failure_restores_state(self):
        files, states = self.persistent_files(), self.states()
        self.system.fail_once = "disable"
        with self.assertRaisesRegex(RuntimeError, "previous lifecycle state restored"):
            self.controller.switch(6, "1")
        self.assertEqual(self.persistent_files(), files)
        self.assertEqual(self.states(), states)

    def test_marker_write_failure_restores_previous_selection_and_services(self):
        self.controller.switch(5)
        files, states = self.persistent_files(), self.states()
        real_write = switch.control.atomic_write
        failed = False
        def write(path, *args):
            nonlocal failed
            if path == self.controller.path(switch.SELECTION) and not failed:
                failed = True
                raise OSError("disk full")
            return real_write(path, *args)
        with patch.object(switch.control, "atomic_write", write):
            with self.assertRaisesRegex(RuntimeError, "previous lifecycle state restored"):
                self.controller.switch(6, "1")
        self.assertEqual(self.persistent_files(), files)
        self.assertEqual(self.states(), states)

    def test_repeat_selection_does_not_restart_or_rewrite(self):
        self.controller.switch(6, "1")
        marker = self.controller.path(switch.SELECTION)
        before = marker.stat().st_mtime_ns
        self.system.calls.clear()
        result = self.controller.switch(6, "1")
        self.assertFalse(result["changed"])
        self.assertEqual(marker.stat().st_mtime_ns, before)
        self.assertFalse(any(c[0] == "systemctl" and c[1] in ("start", "stop", "enable", "disable") for c in self.system.calls))

    def test_external_watchdog_refuses_before_mutations(self):
        self.system.units["vpn-watchdog.timer"]["ActiveState"] = "active"
        files = self.persistent_files()
        with self.assertRaisesRegex(ValueError, "external watchdog"):
            self.controller.switch(6, "1")
        self.assertEqual(files, self.persistent_files())
        self.assertTrue(all(c[0] == "systemctl" and c[1] == "show" for c in self.system.calls))

    def test_missing_or_masked_target_refuses_before_mutations(self):
        for state in ("not-found", "masked"):
            self.system.units["snell6@1.service"]["LoadState"] = state
            files = self.persistent_files()
            with self.assertRaisesRegex(ValueError, "not installed"):
                self.controller.switch(6, "1")
            self.assertEqual(files, self.persistent_files())

    def test_corrupt_selection_fails_closed_and_legacy_absence_is_supported(self):
        self.assertIsNone(switch.read_selection(self.root))
        path = self.controller.path(switch.SELECTION)
        path.parent.mkdir(parents=True)
        path.write_text('{"version":6,"slot":"1"}')
        with self.assertRaises(ValueError):
            self.controller.switch(5)
        self.assertFalse(self.system.calls)

    def test_unsupported_arguments_do_not_mutate(self):
        for version, slot in ((4, None), (5, "1"), (6, None), (6, "9")):
            files = self.persistent_files()
            with self.assertRaises(ValueError):
                self.controller.switch(version, slot)
            self.assertEqual(files, self.persistent_files())

    def test_changed_endpoint_configuration_refuses_before_mutations(self):
        (self.directory / "config.json").write_text('{}')
        files = self.persistent_files()
        with self.assertRaisesRegex(ValueError, "edited externally"):
            self.controller.switch(6, "1")
        self.assertEqual(files, self.persistent_files())

    def test_v5_listener_failure_does_not_commit_selection(self):
        self.controller.switch(6, "1")
        files, states = self.persistent_files(), self.states()
        self.controller.probe = lambda *args: (_ for _ in ()).throw(ConnectionRefusedError("no listener"))
        with self.assertRaisesRegex(RuntimeError, "previous lifecycle state restored"):
            self.controller.switch(5)
        self.assertEqual(self.persistent_files(), files)
        self.assertEqual(self.states(), states)

    def test_backup_contains_lifecycle_and_unchanged_configuration(self):
        result = self.controller.switch(6, "1")
        backup = json.loads((Path(result["backup"]) / "before.json").read_text())
        self.assertEqual(backup["units"]["snell.service"]["ActiveState"], "active")
        self.assertIn("/etc/snell/snell-server.conf", backup["files"])
        self.assertIn("/etc/snell6/endpoints/1/config.json", backup["files"])
        if os.name == "posix":
            self.assertEqual(Path(result["backup"]).stat().st_mode & 0o777, 0o700)
            self.assertEqual((Path(result["backup"]) / "before.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.controller.path(switch.SELECTION).stat().st_mode & 0o777, 0o644)

    def test_v5_authentication_uses_client_version4_when_pinned_core_is_installed(self):
        endpoints = switch.helper("snell6-endpoints")
        endpoints.CORE_SHA256 = hashlib.sha256(b"core").hexdigest()
        core = self.controller.path(endpoints.CORE_BASE) / endpoints.CORE_SHA256 / "sing-box"
        core.parent.mkdir(parents=True)
        core.write_bytes(b"core")
        calls = []
        self.controller.probe = lambda value, binary, run: calls.append((value, binary))
        with patch.object(switch, "helper", lambda name: endpoints):
            result = self.controller.switch(5)
        self.assertEqual(result["verification"], "authenticated")
        self.assertEqual(calls[0][0]["version"], 4)
        self.assertEqual(calls[0][0]["psk"], "keep")
        self.assertEqual(calls[0][1], core)

    def test_switch_restores_missing_owned_firewall_before_probe(self):
        self.assertFalse(self.system.rules)
        self.controller.probe = lambda *args: self.assertEqual(len(self.system.rules), 1)
        result = self.controller.switch(6, "1")
        self.assertEqual(len(self.system.rules), 1)
        backup = json.loads((Path(result["backup"]) / "before.json").read_text())
        self.assertFalse(backup["firewall"]["present"])

    def test_readiness_failure_restores_exact_firewall_absence(self):
        self.controller.probe = lambda *args: (_ for _ in ()).throw(TimeoutError("injected"))
        with self.assertRaisesRegex(RuntimeError, "previous lifecycle state restored"):
            self.controller.switch(6, "1")
        self.assertFalse(self.system.rules)

    def test_existing_v5_obfs_settings_are_preserved_and_sent_to_probe(self):
        config = self.root / "etc/snell/snell-server.conf"
        for mode in ("http", "tls", "off", "none"):
            with self.subTest(mode=mode):
                content = "[snell-server]\nlisten=0.0.0.0:1488\npsk=keep\nobfs=" + mode + "\nobfs-host=cover.example\n"
                config.write_text(content)
                probes = []
                self.controller.probe = lambda value, *args: probes.append(value)
                self.controller.switch(5)
                self.assertEqual(config.read_text(), content)
                self.assertEqual(probes[0]["version"], 4)
                self.assertEqual(probes[0]["obfs_mode"], "none" if mode == "off" else mode)
                self.assertEqual(probes[0]["obfs_host"], "cover.example")

    def test_probe_renders_pinned_v4_obfs_schema_and_keeps_v6_free_of_obfs(self):
        endpoints = switch.helper("snell6-endpoints")
        for version, mode in ((4, "http"), (4, "tls"), (4, "none"), (6, "default")):
            with self.subTest(version=version, mode=mode):
                value = dict(version=version, port=20000, psk="shared", mode=mode,
                             obfs_mode=mode, obfs_host="cover.example")
                captured = []
                def check(*args):
                    captured.append(json.loads(Path(args[-1]).read_text())["outbounds"][0])
                    raise RuntimeError("stop after native check boundary")
                with patch.object(endpoints.socket, "create_connection", return_value=MagicMock()):
                    with self.assertRaisesRegex(RuntimeError, "native check boundary"):
                        endpoints.endpoint_probe(value, Path("core"), check)
                outbound = captured[0]
                if version == 4:
                    self.assertEqual(outbound["obfs_mode"], mode)
                    self.assertEqual(outbound["obfs_host"], "cover.example")
                    self.assertNotIn("mode", outbound)
                else:
                    self.assertEqual(outbound["mode"], "default")
                    self.assertNotIn("obfs_mode", outbound)
                    self.assertNotIn("obfs_host", outbound)


if __name__ == "__main__":
    unittest.main()
