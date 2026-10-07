"""Run on Linux: endpoint/file/SQLite transactions at the system command seam."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("snell6_endpoints", Path(__file__).resolve().parents[1] / "scripts/snell6-endpoints.py")
snell6 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snell6)


class System:
    def __init__(self):
        self.calls, self.rules = [], set()
        self.states = {"snell6@%d.service" % i: {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"}
                       for i in range(1, 9)}
        self.states["snell.service"] = {"LoadState": "not-found", "ActiveState": "inactive", "UnitFileState": "disabled"}
        self.fail_once = None

    def __call__(self, *args):
        self.calls.append(args)
        action = args[2] if args[0] == "iptables" else args[1]
        if self.fail_once == action:
            self.fail_once = None
            raise snell6.Error("injected command failure")
        if args[0] == "iptables":
            rule = tuple(args[4:])
            if action == "-C" and rule not in self.rules:
                error = snell6.Error("absent rule")
                error.returncode = 1
                raise error
            if action == "-I":
                self.rules.add(rule)
            elif action == "-D":
                self.rules.remove(rule)
            return ""
        if args[0] != "systemctl":
            return ""  # Native checker boundary; real binary is covered separately.
        if action == "daemon-reload":
            return ""
        unit = args[-1] if action == "is-active" else args[2]
        state = self.states[unit]
        if action == "show":
            return "\n".join(k + "=" + v for k, v in state.items())
        if action == "start":
            state["ActiveState"] = "active"
        elif action == "stop":
            state["ActiveState"] = "inactive"
        elif action == "enable":
            state["UnitFileState"] = "enabled"
        elif action == "disable":
            state["UnitFileState"] = "disabled"
        elif action == "is-active" and state["ActiveState"] != "active":
            raise snell6.Error("inactive")
        return ""


class Endpoints(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("Linux ownership, symlink and flock semantics required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "source-core"
        self.binary.write_bytes(b"\x7fELF\x02" + b"\x00" * 13 + b"\x3e\x00" + b"synthetic-core")
        self.patch = patch.object(snell6, "CORE_SHA256", hashlib.sha256(self.binary.read_bytes()).hexdigest())
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.system = System()
        self.probes = []
        self.fail_probe_once = False

        def probe(value, core, runner):
            self.probes.append(value["endpoint_id"])
            if self.fail_probe_once:
                self.fail_probe_once = False
                raise snell6.Error("injected readiness failure")

        self.manager = snell6.Manager(self.root, self.system, probe, lambda value: None)
        self.manager.account = lambda: os.getgid()
        self.db_path = self.root / "subscriptions.db"
        self.db = sqlite3.connect(self.db_path)
        self.addCleanup(self.db.close)
        self.db.executescript("CREATE TABLE users(id TEXT PRIMARY KEY,snell_uri TEXT,revision INTEGER,updated_at TEXT,subscription_token TEXT,mieru_uri TEXT);"
                              "CREATE TABLE user_connection_groups(user_id TEXT PRIMARY KEY,document_json TEXT);")
        self.old = "snell://v5-secret@192.0.2.1:1488/?version=5#Keep-v5"
        self.foreign = "snell://foreign-secret@198.51.100.8:21555/?version=6&mode=default#Foreign"
        self.db.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", ("user-1", self.old + "\n" + self.foreign, 4, "old", "keep-token", "keep-mieru"))
        self.db.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", ("user-2", self.old, 7, "old", "keep-token-2", "keep-mieru-2"))
        self.db.commit()

    def create(self, slot=1, **changes):
        return self.manager.apply(slot, dict(server_host="192.0.2.1", **changes), create=True, source=self.binary, db_path=self.db_path)

    def snapshot(self, slot=1):
        directory = self.manager.directory(slot)
        return {name: os.readlink(directory / name) if (directory / name).is_symlink() else (directory / name).read_bytes()
                for name in snell6.FILES}

    def user(self, uid="user-1"):
        return self.db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    def test_create_uses_new_identity_no_v5_or_subscription_mutation(self):
        original = self.user()
        result = self.create()
        endpoint = self.manager.load(1)
        self.assertTrue(result["running_checked"])
        self.assertEqual(len(endpoint["endpoint_id"]), 32)
        self.assertEqual(endpoint["mode"], "default")
        self.assertEqual(self.user(), original)
        config = json.loads((self.manager.directory(1) / "config.json").read_text())
        self.assertEqual([o["type"] for o in config["outbounds"]], ["socks"])
        self.assertEqual(len(self.probes), 1)
        self.assertEqual(len(self.system.rules), 1)
        self.assertEqual((self.manager.directory(1) / "endpoint.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.manager.directory(1) / "config.json").stat().st_mode & 0o777, 0o640)

    def test_repeated_create_is_noop_preserves_identity_keys_and_running_service(self):
        self.create()
        before = self.snapshot()
        self.system.calls.clear()
        result = self.create()
        self.assertFalse(result["changed"])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any(c[:2] == ("systemctl", "stop") for c in self.system.calls))
        self.assertEqual(len(self.probes), 1)

    def test_publish_adds_only_to_explicit_user_and_repeat_does_not_bump_revision(self):
        self.create()
        other = self.user("user-2")
        result = self.manager.publish(1, "user-1", self.db_path)
        self.assertTrue(result["changed"])
        user = self.user()
        self.assertEqual(user[1].splitlines()[:2], [self.old, self.foreign])
        self.assertEqual(len(user[1].splitlines()), 3)
        self.assertEqual(user[2], 5)
        self.assertEqual(user[4:], ("keep-token", "keep-mieru"))
        self.assertFalse(self.manager.publish(1, "user-1", self.db_path)["changed"])
        self.assertEqual(self.user(), user)
        self.assertEqual(self.user("user-2"), other)

    def test_set_updates_only_bound_uri_and_exact_group_copy(self):
        self.create()
        self.manager.publish(1, "user-1", self.db_path)
        old_link = self.user()[1].splitlines()[-1]
        group = {"profiles": [{"id": "keep-profile", "name": "User alias", "uri": old_link}], "groups": [{"id": "keep-group"}]}
        self.db.execute("INSERT INTO user_connection_groups VALUES (?,?)", ("user-1", json.dumps(group)))
        self.db.commit()
        identity = self.manager.load(1)["endpoint_id"]
        self.manager.apply(1, {"name": "New endpoint name"}, source=self.binary, db_path=self.db_path)
        self.assertEqual(self.manager.load(1)["endpoint_id"], identity)
        updated = self.user()[1].splitlines()
        self.assertEqual(updated[:2], [self.old, self.foreign])
        self.assertNotEqual(updated[-1], old_link)
        after = json.loads(self.db.execute("SELECT document_json FROM user_connection_groups").fetchone()[0])
        self.assertEqual(after["profiles"][0]["id"], "keep-profile")
        self.assertEqual(after["profiles"][0]["name"], "User alias")
        self.assertEqual(after["profiles"][0]["uri"], updated[-1])

    def test_probe_failure_rolls_back_files_database_and_running_service(self):
        self.create()
        self.manager.publish(1, "user-1", self.db_path)
        before, user, rules = self.snapshot(), self.user(), set(self.system.rules)
        self.fail_probe_once = True
        with self.assertRaisesRegex(snell6.Error, "previous state restored"):
            self.manager.apply(1, {"name": "Rejected change"}, source=self.binary, db_path=self.db_path)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.user(), user)
        self.assertEqual(self.system.rules, rules)
        self.assertEqual(self.system.states["snell6@1.service"]["ActiveState"], "active")

    def test_clean_start_failure_removes_only_new_endpoint_files_and_rule(self):
        self.system.fail_once = "start"
        user = self.user()
        with self.assertRaisesRegex(snell6.Error, "previous state restored"):
            self.create()
        self.assertFalse(any((self.manager.directory(1) / name).exists() for name in snell6.FILES))
        self.assertFalse(self.system.rules)
        self.assertEqual(self.user(), user)

    def test_existing_stopped_disabled_and_masked_states_preserved(self):
        self.create()
        for enabled in ("disabled", "masked"):
            self.system.states["snell6@1.service"].update(ActiveState="inactive", UnitFileState=enabled,
                                                         LoadState="masked" if enabled == "masked" else "loaded")
            before_probes = len(self.probes)
            result = self.manager.apply(1, {"name": "Name " + enabled}, source=self.binary, db_path=self.db_path)
            self.assertFalse(result["running_checked"])
            self.assertEqual(self.system.states["snell6@1.service"]["UnitFileState"], enabled)
            self.assertEqual(self.system.states["snell6@1.service"]["ActiveState"], "inactive")
            self.assertEqual(len(self.probes), before_probes)

    def test_new_endpoint_does_not_override_existing_persistent_off(self):
        lifecycle = self.manager.lifecycle()
        permanent, _ = lifecycle.markers("snell6@1.service")
        permanent.parent.mkdir(parents=True)
        permanent.write_text("off")
        result = self.create()
        self.assertFalse(result["running_checked"])
        self.assertEqual(self.system.states["snell6@1.service"]["UnitFileState"], "disabled")
        self.assertTrue(permanent.exists())

    def test_checksum_schema_and_port_failure_precede_endpoint_changes(self):
        self.binary.write_bytes(b"corrupt")
        with self.assertRaisesRegex(snell6.Error, "checksum"):
            self.create()
        self.assertFalse(self.manager.directory(1).exists())
        for changes in ({"port": 443}, {"port": 8443}, {"mode": "invalid"},
                        {"userkey": "not-qualified"}, {"quic-proxy-mode": True}):
            with self.subTest(changes=changes), self.assertRaises(snell6.Error):
                self.create(**changes)
        self.assertFalse(self.manager.directory(1).exists())

    def test_modes_reconfigure_bound_links_and_preserve_identity(self):
        self.create()
        self.manager.publish(1, "user-1", self.db_path)
        before = self.manager.load(1)
        for mode in ("unshaped", "unsafe-raw", "default"):
            self.manager.apply(1, {"mode": mode}, source=self.binary, db_path=self.db_path)
            value = self.manager.load(1)
            for key in ("endpoint_id", "psk", "port"):
                self.assertEqual(value[key], before[key])
            self.assertEqual(snell6.render(value)["inbounds"][0]["mode"], mode)
            self.assertIn("mode=" + mode, self.user()[1])

    def test_prepare_only_does_not_start_or_enable_new_endpoint(self):
        self.manager.apply(1, {"server_host": "192.0.2.1"}, create=True,
                           source=self.binary, prepare_only=True)
        self.assertEqual(self.system.states["snell6@1.service"]["ActiveState"], "inactive")
        self.assertEqual(self.system.states["snell6@1.service"]["UnitFileState"], "disabled")
        self.assertFalse(self.probes)

    def test_external_import_is_additive_and_idempotent(self):
        link = "snell://external-psk@203.0.113.17:22000?version=6&mode=default#External"
        before = self.user()
        self.assertTrue(snell6.import_link(self.db_path, "user-1", link))
        self.assertEqual(self.user()[1], before[1] + "\n" + link)
        self.assertEqual(self.user()[2], before[2] + 1)
        self.assertFalse(snell6.import_link(self.db_path, "user-1", link))
        self.assertEqual(self.user()[2], before[2] + 1)

    def test_user_selection_uses_names_and_preserves_current_user(self):
        self.db.execute("ALTER TABLE users ADD COLUMN nickname TEXT")
        self.db.execute("UPDATE users SET nickname='Alice' WHERE id='user-1'")
        self.db.execute("UPDATE users SET nickname='Bob' WHERE id='user-2'")
        self.db.commit()
        with patch("builtins.input", return_value="2"):
            self.assertEqual(snell6.select_user(self.db_path), "user-2")
        with patch("builtins.input", side_effect=AssertionError("Unexpected prompt")):
            self.assertEqual(snell6.select_user(self.db_path, "user-1"), "user-1")

    def test_subscription_menu_never_enters_server_management(self):
        from unittest.mock import Mock
        import contextlib, io
        output = io.StringIO()
        manager = Mock()
        with patch.object(snell6, "database_path", return_value=self.db_path), \
             patch.object(snell6, "select_user", return_value="user-1"), \
             patch.object(snell6, "endpoint_menu", side_effect=AssertionError("Server menu")), \
             patch("builtins.input", side_effect=["1", "0"]), contextlib.redirect_stdout(output):
            snell6.menu(manager, "user-1")
        self.assertEqual(manager.mock_calls, [])
        self.assertNotIn("Настройки подключения", output.getvalue())
        self.assertNotIn("Создать подключение", output.getvalue())
        self.assertIn("Подписка пользователя", output.getvalue())

    def test_subscription_removal_preserves_v5_foreign_and_other_user(self):
        first = "snell://key@203.0.113.17:22000?version=6&mode=default#First"
        second = "snell://other@203.0.113.18:22001?version=6&mode=default#Second"
        before = self.user()
        snell6.import_link(self.db_path, "user-1", first)
        snell6.import_link(self.db_path, "user-1", second)
        snell6.import_link(self.db_path, "user-2", first)
        snell6.remove_subscription_link(self.db_path, "user-1", first)
        self.assertEqual(self.user()[1], before[1] + "\n" + second)
        self.assertEqual(snell6.subscription_links(self.db_path, "user-1"), [line for line in before[1].splitlines() if "version=6" in line] + [second])
        self.assertIn(first, snell6.subscription_links(self.db_path, "user-2"))

    def test_configuration_conflict_rejected_without_overwrite(self):
        self.create()
        config = self.manager.directory(1) / "config.json"
        config.write_text("foreign change")
        with self.assertRaisesRegex(snell6.Error, "edited externally"):
            self.manager.apply(1, {"name": "new"}, source=self.binary)
        self.assertEqual(config.read_text(), "foreign change")

    def test_existing_closed_firewall_policy_is_not_reopened(self):
        self.create()
        self.system.rules.clear()
        self.manager.apply(1, {"name": "Rename only"}, source=self.binary)
        self.assertFalse(self.system.rules)
        self.fail_probe_once = True
        with self.assertRaises(snell6.Error):
            self.manager.apply(1, {"name": "Rejected rename"}, source=self.binary)
        self.assertFalse(self.system.rules)

    def test_endpoint_slots_reserve_distinct_ports_even_when_stopped(self):
        self.create()
        self.system.states["snell6@1.service"]["ActiveState"] = "inactive"
        self.create(slot=2)
        first, second = self.manager.load(1), self.manager.load(2)
        self.assertNotEqual(first["port"], second["port"])
        self.assertNotEqual(first["endpoint_id"], second["endpoint_id"])
        with self.assertRaisesRegex(snell6.Error, "reserved"):
            self.create(slot=3, port=first["port"])

    def test_boot_hook_restores_only_owned_rule_and_respects_off(self):
        self.create()
        self.system.rules = {("foreign-rule",)}
        self.manager.ensure_firewall(1)
        self.assertIn(("foreign-rule",), self.system.rules)
        self.assertEqual(len(self.system.rules), 2)
        self.system.rules = {("foreign-rule",)}
        permanent, _ = self.manager.lifecycle().markers("snell6@1.service")
        permanent.parent.mkdir(parents=True)
        permanent.write_text("off")
        self.manager.ensure_firewall(1)
        self.assertEqual(self.system.rules, {("foreign-rule",)})

    def test_explicit_firewall_closed_intent_survives_start_hook_without_restart(self):
        self.create()
        self.system.calls.clear()
        self.manager.apply(1, {"firewall_open": False}, source=self.binary)
        self.manager.ensure_firewall(1)
        self.assertFalse(self.system.rules)
        self.assertFalse(self.manager.load(1)["firewall_open"])
        self.assertFalse(any(c[:2] == ("systemctl", "stop") for c in self.system.calls))

    def test_missing_template_fails_before_creating_endpoint_or_installing_core(self):
        self.system.states["snell6@1.service"]["LoadState"] = "not-found"
        with self.assertRaisesRegex(snell6.Error, "template"):
            self.create()
        self.assertFalse(self.manager.directory(1).exists())
        self.assertFalse(self.manager.path(snell6.CORE_BASE).exists())


if __name__ == "__main__":
    unittest.main()
