import contextlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("watchdog_health", ROOT / "scripts/watchdog-health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


def settings(**kwargs):
    value = dict(kind="tcp", host="127.0.0.1", port=12345, path="/health",
                 failures=2, cooldown=60, max_restarts=2, timeout=1)
    value.update(kwargs)
    return value


class Services:
    def __init__(self):
        self.inhibited = False
        self.conflicting = False
        self.live = dict(LoadState="loaded", ActiveState="active", MainPID="123",
                         UnitFileState="enabled", Type="simple")
        self.restarts = []
        self.failure = False

    def allowed(self, unit):
        return not self.inhibited

    def conflicts(self):
        return [{"unit": "vpn-watchdog.service", "conflict": self.conflicting}]

    @contextlib.contextmanager
    def lock(self):
        yield

    def command(self, *args):
        if args[1] == "show":
            return "\n".join(k + "=" + v for k, v in self.live.items())
        if args[1] != "restart":
            raise AssertionError("Unexpected mutation: " + str(args))
        self.restarts.append(args[2])
        if self.failure:
            raise RuntimeError("injected systemctl failure")
        return ""


class HealthContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.services = Services()
        self.clock = 1000
        self.healthy = False
        self.engine = health.Health(self.root, self.services.command,
                                   lambda spec, pid: (self.healthy, "synthetic probe"),
                                   lambda: self.clock, self.services)
        self.engine.configure("set", "snell", settings())

    def outcome(self):
        return self.engine.check()["units"][0]

    def test_consecutive_failures_cooldown_and_persistent_restart_limit(self):
        self.assertEqual(self.outcome()["status"], "unhealthy")
        self.assertEqual(self.outcome()["status"], "restarted")
        self.outcome()
        self.assertEqual(self.outcome()["status"], "cooldown")
        self.clock += 61
        self.assertEqual(self.outcome()["status"], "restarted")
        self.clock += 61
        self.outcome()
        self.assertEqual(self.outcome()["status"], "exhausted")
        self.assertEqual(len(self.services.restarts), 2)
        # Healthy intervals, reconfiguration and remove/add do not replenish.
        self.healthy = True
        self.outcome()
        self.engine.configure("remove", "snell")
        self.engine.configure("set", "snell", settings())
        self.healthy = False
        self.outcome()
        self.assertEqual(self.outcome()["status"], "exhausted")
        self.engine.configure("reset", "snell")
        self.outcome()
        self.assertEqual(self.outcome()["status"], "restarted")

    def test_new_process_instance_resets_only_failure_streak(self):
        self.outcome()
        self.services.live["MainPID"] = "456"
        self.assertEqual(self.outcome()["status"], "unhealthy")
        self.assertEqual(self.services.restarts, [])

    def test_monitor_only_configuration_does_not_restart(self):
        self.engine.configure("set", "snell", settings(max_restarts=0))
        self.outcome()
        self.assertEqual(self.outcome()["status"], "monitor-only")
        self.assertEqual(self.services.restarts, [])

    def test_healthy_interval_breaks_failure_streak(self):
        self.outcome()
        self.healthy = True
        self.assertEqual(self.outcome()["status"], "healthy")
        self.healthy = False
        self.assertEqual(self.outcome()["status"], "unhealthy")
        self.assertEqual(self.services.restarts, [])

    def test_off_inactive_and_masks_never_restart(self):
        self.outcome()
        self.services.inhibited = True
        self.assertEqual(self.outcome()["status"], "skipped")
        self.services.inhibited = False
        self.services.live["ActiveState"] = "inactive"
        self.assertEqual(self.outcome()["status"], "skipped")
        self.services.live.update(ActiveState="active", UnitFileState="masked-runtime")
        self.assertEqual(self.outcome()["status"], "skipped")
        self.assertEqual(self.services.restarts, [])

    def test_external_watcher_blocks_set_and_check_without_mutating_owner(self):
        self.services.conflicting = True
        with self.assertRaisesRegex(ValueError, "watchdog"):
            self.engine.configure("set", "snell", settings())
        self.assertEqual(self.engine.check()["status"], "blocked")
        self.assertEqual(self.services.restarts, [])

    def test_state_change_during_probe_does_not_restart_new_or_stopped_process(self):
        self.outcome()
        def probe(spec, pid):
            self.services.live["ActiveState"] = "inactive"
            return False, "fixture"
        self.engine.probe = probe
        self.assertEqual(self.outcome()["status"], "skipped")
        self.assertEqual(self.services.restarts, [])

    def test_external_watcher_start_during_probe_is_detected(self):
        self.outcome()
        def probe(spec, pid):
            self.services.conflicting = True
            return False, "fixture"
        self.engine.probe = probe
        self.assertEqual(self.outcome()["status"], "blocked")
        self.assertEqual(self.services.restarts, [])

    def test_failed_restart_consumes_attempt_and_survives_new_engine(self):
        self.services.failure = True
        self.outcome()
        self.assertEqual(self.outcome()["status"], "restart-failed")
        new = health.Health(self.root, self.services.command, controller=self.services)
        self.assertEqual(new.report()["counters"]["units"]["snell.service"]["attempts"], 1)

    def test_installer_lock_skips_without_probe_or_state_mutation(self):
        import fcntl
        lock = self.root / health.INSTALL_LOCK.lstrip("/")
        before = self.engine.read_json(health.STATE)
        with lock.open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.engine.check()["status"], "skipped")
        self.assertEqual(self.engine.read_json(health.STATE), before)

    def test_report_is_read_only_and_set_does_not_enable_timer(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.engine.report()
        after = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(self.services.restarts, [])

    def test_invalid_remote_targets_and_corrupt_counters_fail_closed(self):
        for changes in ({"host": "example.com"}, {"host": "192.0.2.1"}, {"path": "//external/path"},
                        {"path": "/health?token=secret"}, {"path": "/health\r\nInjected: yes"},
                        {"port": 0}, {"max_restarts": True}):
            value = settings()
            value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.engine.configure("set", "snell", value)
        self.engine.save(health.STATE, {"schema": 1, "units": {"snell.service": {"attempts": -1}}})
        with self.assertRaisesRegex(ValueError, "counters"):
            self.engine.check()
        self.assertEqual(self.services.restarts, [])

    def test_real_local_tcp_and_http_probes_never_follow_redirects(self):
        value = settings()
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            value["port"] = server.getsockname()[1]
            self.assertTrue(health.local_probe(value, os.getpid())[0])
        self.assertFalse(health.local_probe(value, os.getpid())[0])
        class Handler(http.server.BaseHTTPRequestHandler):
            code = 204
            def do_GET(self):
                self.send_response(self.code)
                self.send_header("Location", "http://192.0.2.1/never-follow")
                self.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            value.update(kind="http", port=server.server_port)
            self.assertTrue(health.local_probe(value, os.getpid())[0])
            Handler.code = 302
            self.assertEqual(health.local_probe(value, os.getpid()), (False, "local HTTP status 302"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class XrayProbeContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.proc = Path(self.temp.name)
        self.process(100, 1, "x-ui", children="101")
        self.process(101, 100, "helper")

    def process(self, pid, ppid, executable, children="", state="S", thread=None):
        directory = self.proc / str(pid)
        tasks = directory / "task" / str(thread or pid)
        tasks.mkdir(parents=True, exist_ok=True)
        (tasks / "children").write_text(children)
        # Linux stat fields 3..22: state, ppid, ..., starttime.
        fields = [state, str(ppid)] + ["0"] * 17 + [str(pid * 10)]
        (directory / "stat").write_text(str(pid) + " (name with ) spaces) " + " ".join(fields))
        (directory / "exe").symlink_to("/usr/bin/" + executable)

    def test_unrelated_xray_does_not_satisfy_xui_probe(self):
        self.process(999, 1, "xray")
        self.assertFalse(health.xray_child_probe(100, 1, self.proc)[0])

    def test_descendant_spawned_by_worker_thread_is_detected(self):
        thread = self.proc / "101/task/102"
        thread.mkdir()
        (thread / "children").write_text("103")
        self.process(103, 101, "xray-linux-amd64")
        self.assertTrue(health.xray_child_probe(100, 1, self.proc)[0])

    def test_zombie_and_reparented_processes_are_not_healthy(self):
        for state, ppid in (("Z", 100), ("S", 999)):
            with self.subTest(state=state, ppid=ppid):
                (self.proc / "101/exe").unlink()
                self.process(101, ppid, "xray", state=state)
                self.assertFalse(health.xray_child_probe(100, 1, self.proc)[0])

    def test_process_inspection_is_bounded(self):
        (self.proc / "100/task/100/children").write_text(" ".join(str(i) for i in range(1000, 1300)))
        outcome = health.xray_child_probe(100, 1, self.proc)
        self.assertFalse(outcome[0])
        self.assertIn("bounded", outcome[1])
        self.assertFalse(health.xray_child_probe(100, 0, self.proc)[0])

    def test_pid_reuse_during_executable_inspection_is_rejected(self):
        original = os.readlink
        def changed(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            stat = self.proc / "101/stat"
            stat.write_text(stat.read_text().replace("1010", "1011"))
            return value
        (self.proc / "101/exe").unlink()
        self.process(101, 100, "xray")
        with mock.patch.object(health.os, "readlink", side_effect=changed):
            self.assertFalse(health.xray_child_probe(100, 1, self.proc)[0])


class BootstrapServices:
    def __init__(self):
        self.units = {name: dict(LoadState="loaded", ActiveState="active", MainPID="123",
                                UnitFileState="enabled", Type="simple")
                      for name in ("x-ui.service", health.TIMER, "tuna-healthcheck.service")}
        self.units[health.TIMER].update(ActiveState="inactive", MainPID="0", UnitFileState="disabled")
        self.mutations = []
        self.fail = None

    def command(self, *args):
        action, unit = args[1:3]
        if action == "show":
            return "\n".join(k + "=" + v for k, v in self.units.get(unit, {"LoadState": "not-found"}).items())
        self.mutations.append((action, unit))
        if unit != health.TIMER:
            raise AssertionError("Bootstrap must not mutate a service")
        live = self.units[unit]
        if action in ("enable", "disable"):
            live["UnitFileState"] = {"enable": "enabled", "disable": "disabled"}[action]
        elif action in ("start", "stop"):
            live["ActiveState"] = {"start": "active", "stop": "inactive"}[action]
        else:
            raise AssertionError("Unexpected timer action: " + action)
        # Simulate commands that modify state before reporting a failure.
        if action == self.fail:
            raise RuntimeError("injected " + action + " failure")
        return ""


class BootstrapContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.services = BootstrapServices()
        self.engine = health.Health(self.root, self.services.command,
                                   probe=lambda spec, pid: (True, "verified Xray child"))

    def test_explicit_baseline_creates_bounded_check_and_is_idempotent(self):
        result = self.engine.bootstrap(enable_timer=True)
        self.assertEqual(result["status"], "configured")
        check = self.engine.read_json(health.CONFIG)["units"]["x-ui.service"]
        self.assertEqual((check["kind"], check["failures"], check["max_restarts"], check["cooldown"], check["timeout"]),
                         ("xray", 2, 5, 60, 3))
        before = self.engine.path(health.CONFIG).read_bytes()
        mutations = list(self.services.mutations)
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        self.assertEqual(self.engine.path(health.CONFIG).read_bytes(), before)
        self.assertEqual(self.services.mutations, mutations)

    def test_existing_configuration_including_empty_and_invalid_is_never_replaced(self):
        target = self.engine.path(health.CONFIG)
        target.parent.mkdir(parents=True)
        for content in ('{"schema":1,"units":{}}', "", "invalid old configuration"):
            target.write_text(content)
            self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
            self.assertEqual(target.read_text(), content)
        self.assertEqual(self.services.mutations, [])

    def test_unattended_bootstrap_preserves_existing_disabled_or_stopped_timer(self):
        for enabled, active in (("disabled", "inactive"), ("disabled", "active"), ("enabled", "inactive")):
            self.services.units[health.TIMER].update(UnitFileState=enabled, ActiveState=active)
            self.assertEqual(self.engine.bootstrap()["status"], "preserved")
        self.assertFalse(self.engine.path(health.CONFIG).exists())
        self.assertEqual(self.services.mutations, [])

    def test_explicit_baseline_still_preserves_lifecycle_disable_stop_off_and_mask(self):
        controller = self.engine.controller
        for unit in ("x-ui.service", health.TIMER, "tuna-healthcheck.service"):
            for marker in controller.markers(unit):
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text("inhibited")
                self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
                marker.unlink()
        controller.save({"version": 1, "units": {health.TIMER: {"off": False, "autostart": False}}})
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        controller.save({"version": 1, "units": {}})
        self.services.units[health.TIMER]["UnitFileState"] = "masked-runtime"
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        self.assertFalse(self.engine.path(health.CONFIG).exists())
        self.assertEqual(self.services.mutations, [])

    def test_inactive_xui_and_external_watchdog_prevent_setup(self):
        self.services.units["x-ui.service"]["ActiveState"] = "inactive"
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        self.services.units["x-ui.service"]["ActiveState"] = "active"
        self.services.units["vpn-watchdog.service"] = dict(self.services.units["x-ui.service"])
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        self.assertFalse(self.engine.path(health.CONFIG).exists())
        self.assertEqual(self.services.mutations, [])

    def test_partial_enable_or_start_failure_restores_configuration_and_timer(self):
        for failure in ("enable", "start"):
            self.services.fail = failure
            with self.subTest(failure=failure), self.assertRaisesRegex(RuntimeError, "injected"):
                self.engine.bootstrap(enable_timer=True)
            self.assertFalse(self.engine.path(health.CONFIG).exists())
            self.assertEqual(self.services.units[health.TIMER]["ActiveState"], "inactive")
            self.assertEqual(self.services.units[health.TIMER]["UnitFileState"], "disabled")

    def test_failed_config_write_never_activates_timer(self):
        with mock.patch.object(self.engine, "save", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.engine.bootstrap(enable_timer=True)
        self.assertFalse(self.engine.path(health.CONFIG).exists())
        self.assertEqual(self.services.mutations, [])

    def test_existing_restart_budget_is_preserved(self):
        state = {"schema": 1, "units": {"x-ui.service": {"failures": 0, "attempts": 3, "last_restart": 100, "pid": 123}}}
        self.engine.save(health.STATE, state)
        before = self.engine.path(health.STATE).read_bytes()
        self.engine.bootstrap(enable_timer=True)
        self.assertEqual(self.engine.path(health.STATE).read_bytes(), before)

    def test_unrecognized_xray_process_layout_never_activates_recovery(self):
        self.engine.probe = lambda spec, pid: (False, "no Xray child")
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        self.assertFalse(self.engine.path(health.CONFIG).exists())
        self.assertEqual(self.services.mutations, [])

    def test_xui_stop_during_setup_probe_does_not_create_configuration(self):
        def stopped(spec, pid):
            self.services.units["x-ui.service"]["ActiveState"] = "inactive"
            return True, "Xray was running"
        self.engine.probe = stopped
        self.assertEqual(self.engine.bootstrap(enable_timer=True)["status"], "preserved")
        self.assertFalse(self.engine.path(health.CONFIG).exists())
        self.assertEqual(self.services.mutations, [])

    def test_rollback_failure_is_reported_instead_of_claiming_restoration(self):
        original = self.services.command
        def command(*args):
            if args[1] == "stop":
                raise RuntimeError("cannot stop timer")
            return original(*args)
        self.engine.run = command
        self.services.fail = "start"
        with self.assertRaisesRegex(RuntimeError, "rollback incomplete"):
            self.engine.bootstrap(enable_timer=True)
        self.assertFalse(self.engine.path(health.CONFIG).exists())

    def test_inherited_installer_lock_works_and_wrong_descriptor_is_rejected(self):
        import fcntl
        path = self.engine.path(health.INSTALL_LOCK)
        path.parent.mkdir(parents=True)
        with path.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "in progress"):
                self.engine.bootstrap(enable_timer=True)
            self.assertEqual(self.engine.bootstrap(install_lock_fd=lock.fileno(), new_timer=True)["status"], "configured")
        with tempfile.TemporaryFile() as wrong:
            with self.assertRaisesRegex(ValueError, "descriptor"):
                self.engine.bootstrap(install_lock_fd=wrong.fileno(), new_timer=True)
        with self.assertRaisesRegex(ValueError, "inherited"):
            self.engine.bootstrap(new_timer=True)


if __name__ == "__main__":
    unittest.main()
