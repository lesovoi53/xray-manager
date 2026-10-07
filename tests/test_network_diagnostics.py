"""Fixture-only diagnostics contracts: no network/systemd mutations."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("network_diagnostics",
    Path(__file__).resolve().parents[1] / "scripts" / "network-diagnostics.py")
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []

    def write(self, path, value):
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8", newline="\n")

    def runner(self, args, **kwargs):
        self.calls.append((args, kwargs))
        value = ""
        if args[0] == "systemctl":
            value = ("Id=vpn-watchdog.service\nActiveState=active\nLoadState=loaded\n"
                     "ExecStart=SECRET_ARGUMENT\nEnvironment=SECRET_ENV\n\n"
                     "Id=x-ui.service\nMainPID=123\nLimitNOFILE=65535\n"
                     "DropInPaths=/etc/systemd/system/x-ui.service.d/custom.conf\n")
        return subprocess.CompletedProcess(args, 0, value, "")

    def test_snapshot_is_read_only_and_filters_private_properties(self):
        self.write("/etc/os-release", 'PRETTY_NAME="Debian"\nID=debian\nSECRET=never-copy\n')
        self.write("/proc/meminfo", "MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
        self.write("/proc/stat", "cpu 1 2 3 4\ncpu0 1 2 3 4\ncpu1 1 2 3 4\n")
        self.write("/proc/123/limits", "Max open files            2048                 65535                files\n")
        self.write("/proc/123/fd/0", "not read")
        self.write("/proc/sys/fs/file-nr", "12 0 300\n")
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        report = diagnostics.Collector(self.root, runner=self.runner).collect()
        after = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(report["memory"]["value"]["MemAvailable"], 512)
        self.assertEqual(report["cpu"]["value"]["logical_cpus"], 2)
        process = report["systemd"]["value"]["x-ui.service"]
        self.assertEqual(process["process_nofile"]["value"]["soft"], "2048")
        self.assertEqual(process["process_fd_count"]["value"], 1)
        self.assertTrue(report["warnings"])
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("never-copy", json.dumps(report))
        self.assertNotIn("not read", json.dumps(report))
        for args, kwargs in self.calls:
            self.assertIn(args[0], ("systemctl", "ip", "tc"))
            if args[0] == "systemctl":
                self.assertEqual(args[1], "show")
            self.assertLessEqual(kwargs["timeout"], 2)

    def test_missing_utility_and_timeout_are_not_healthy(self):
        def absent(*args, **kwargs):
            raise FileNotFoundError()
        collector = diagnostics.Collector(self.root, runner=absent)
        self.assertEqual(collector.command("tc")["status"], "not_checked")
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("tc", 1, output="secret-output")
        collector.runner = timeout
        self.assertEqual(collector.command("tc")["reason"], "command timed out: tc")
        collector.deadline = 0
        self.assertIn("budget", collector.command("tc")["reason"])

    def test_failed_command_does_not_echo_arbitrary_output(self):
        runner = lambda args, **kwargs: subprocess.CompletedProcess(args, 1, "secret stdout", "secret stderr")
        report = diagnostics.Collector(self.root, runner=runner).collect()
        self.assertNotIn("secret", json.dumps(report))
        self.assertEqual(report["qdisc"]["status"], "not_checked")

    def test_declarations_preserve_duplicates_without_claiming_effective_origin(self):
        self.write("/etc/sysctl.d/99-custom.conf", "net.ipv4.tcp_congestion_control=bbr\nprivate.token=secret\n")
        self.write("/usr/lib/sysctl.d/99-custom.conf", "net.ipv4.tcp_congestion_control=cubic\n")
        self.write("/proc/sys/net/ipv4/tcp_congestion_control", "reno\n")
        report = diagnostics.Collector(self.root, runner=self.runner).collect()
        self.assertEqual(report["effective_sysctl"]["net.ipv4.tcp_congestion_control"]["value"], "reno\n")
        records = report["sysctl_declarations"]["value"]
        self.assertEqual({record["value"] for record in records}, {"bbr", "cubic"})
        self.assertNotIn("private.token", json.dumps(report))

    def test_redaction_and_bounded_reads(self):
        value = diagnostics.redact({"a": ["https://secret.example/token", "token=abc", "password:xyz",
                                          "12345678-1234-1234-1234-123456789abc"]})
        self.assertNotIn("secret.example", json.dumps(value))
        self.assertNotIn("xyz", json.dumps(value))
        self.assertIn("UUID_REDACTED", json.dumps(value))
        self.write("/huge", "x" * (diagnostics.MAX_BYTES + 1))
        self.assertEqual(diagnostics.Collector(self.root).read("/huge")["status"], "not_checked")


if __name__ == "__main__":
    unittest.main()
