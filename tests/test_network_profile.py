"""Transactional profile tests with fake procfs and command runner; no host changes."""
from contextlib import nullcontext
import importlib.util
import json
import io
from contextlib import redirect_stdout
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("network_profile",
    Path(__file__).resolve().parents[1] / "scripts" / "network-profile.py")
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.fail_once = None
        self.tool = profile.Profile(self.root, run=self.run_command)
        self.tool.lock = nullcontext
        self.before = {"net.ipv4.tcp_congestion_control": "cubic", "net.core.default_qdisc": "fq_codel"}
        for key, value in self.before.items():
            self.write("/proc/sys/" + key.replace(".", "/"), value)
        self.write("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr")

    def write(self, name, value):
        target = self.tool.path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8", newline="\n")

    def run_command(self, *args):
        self.calls.append(args)
        self.assertEqual(args[:2], ("sysctl", "-w"))
        key, value = args[2].split("=", 1)
        if value == self.fail_once:
            self.fail_once = None
            raise RuntimeError("injected write failure")
        self.write("/proc/sys/" + key.replace(".", "/"), value)
        return ""

    def test_plan_is_read_only_and_does_not_run_commands(self):
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        plan = self.tool.plan()
        self.assertTrue(plan["ready"])
        self.assertEqual(plan["current"], self.before)
        self.assertEqual(self.calls, [])
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})
        self.assertFalse(self.tool.path(profile.STATE).parent.exists())

    def test_human_cli_shows_matching_files_without_json_or_mutation(self):
        for key, value in profile.VALUES.items():
            self.write('/proc/sys/' + key.replace('.', '/'), value)
        self.write('/etc/sysctl.d/99-network.conf', profile.CONTENT)
        with patch.object(profile, 'Profile', return_value=self.tool), patch('sys.argv', ['network-profile.py', 'plan', '--human']):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(profile.main(), 0)
        self.assertIn('уже соответствует BBR/fq', output.getvalue())
        self.assertIn('99-network.conf — значения совпадают', output.getvalue())
        self.assertNotIn('"action"', output.getvalue())
        self.assertNotIn('file_preview', output.getvalue())
        self.assertEqual(self.calls, [])
        with patch.object(profile, 'Profile', return_value=self.tool), patch('sys.argv', ['network-profile.py', 'plan', '--json']):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(profile.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), self.tool.plan())

    def test_human_conflict_and_details_keep_real_blocker_visible(self):
        self.write('/etc/sysctl.d/99-network.conf', 'net.core.default_qdisc = fq_codel\n')
        plan = self.tool.plan()
        self.assertFalse(plan['ready'])
        text = profile.human_report(plan, details=True)
        self.assertIn('Применение:           недоступно', text)
        self.assertIn('Возможное переопределение другим файлом:', text)
        self.assertIn('/etc/sysctl.d/99-network.conf:1', text)
        self.assertIn('есть отличающиеся значения', text)
        self.assertEqual(self.calls, [])

    def test_apply_rollback_preserves_original_state_and_unrelated_config(self):
        self.write("/etc/sysctl.d/20-existing.conf", "net.ipv4.ip_forward=1\n")
        self.assertEqual(self.tool.apply()["status"], "applied")
        self.assertEqual(self.tool.effective(), profile.VALUES)
        self.assertTrue(self.tool.path(profile.STATE).exists())
        self.assertEqual(self.tool.rollback()["status"], "restored")
        self.assertEqual(self.tool.effective(), self.before)
        self.assertFalse(self.tool.path(profile.CONFIG).exists())
        self.assertFalse(self.tool.path(profile.STATE).exists())
        self.assertEqual(self.tool.read("/etc/sysctl.d/20-existing.conf"), "net.ipv4.ip_forward=1\n")

    def test_apply_failure_restores_file_and_effective_values(self):
        prior = profile.HEADER + "# previously managed but inactive\n"
        self.write(profile.CONFIG, prior)
        self.fail_once = "fq"
        with self.assertRaisesRegex(RuntimeError, "original runtime and file restored"):
            self.tool.apply()
        self.assertEqual(self.tool.effective(), self.before)
        self.assertEqual(self.tool.read(profile.CONFIG), prior)
        self.assertFalse(self.tool.path(profile.STATE).exists())

    def test_late_or_wildcard_overrides_block_apply(self):
        for name, content in (("/etc/sysctl.conf", "net.core.default_qdisc=fq_codel"),
                              ("/etc/sysctl.d/99-local.conf", "net.ipv4.tcp_*=cubic")):
            with self.subTest(name=name):
                self.write(name, content)
                with self.assertRaisesRegex(ValueError, "later override"):
                    self.tool.apply()
                self.assertEqual(self.calls, [])
                self.tool.path(name).unlink()

    def test_missing_bbr_and_unowned_target_are_blockers(self):
        self.write("/proc/sys/net/ipv4/tcp_available_congestion_control", "cubic reno")
        self.write(profile.CONFIG, "# belongs to user\n")
        plan = self.tool.plan()
        self.assertFalse(plan["ready"])
        self.assertEqual(len(plan["blockers"]), 2)

    def test_second_apply_and_rollback_after_admin_change_are_rejected(self):
        self.tool.apply()
        with self.assertRaisesRegex(ValueError, "existing transaction"):
            self.tool.apply()
        self.write("/proc/sys/net/ipv4/tcp_congestion_control", "reno")
        with self.assertRaisesRegex(ValueError, "Runtime changed"):
            self.tool.rollback()
        self.assertEqual(self.tool.effective()["net.ipv4.tcp_congestion_control"], "reno")
        self.assertTrue(self.tool.path(profile.STATE).exists())

    def test_modified_managed_file_is_preserved_on_rollback(self):
        self.tool.apply()
        self.write(profile.CONFIG, "# manual edit\n")
        with self.assertRaisesRegex(ValueError, "Managed file changed"):
            self.tool.rollback()
        self.assertEqual(self.tool.read(profile.CONFIG), "# manual edit\n")

    def test_failed_rollback_keeps_retryable_snapshot_and_restores_other_key(self):
        self.tool.apply()
        self.fail_once = "cubic"
        with self.assertRaisesRegex(RuntimeError, "Rollback incomplete"):
            self.tool.rollback()
        self.assertEqual(self.tool.effective()["net.core.default_qdisc"], "fq_codel")
        self.assertTrue(self.tool.path(profile.STATE).exists())
        self.assertFalse(self.tool.path(profile.CONFIG).exists())
        self.assertEqual(self.tool.rollback()["status"], "restored")
        self.assertEqual(self.tool.effective(), self.before)

    def test_interrupted_transaction_before_config_write_can_rollback(self):
        self.tool.save_snapshot({"schema_version": 1, "phase": "applying", "before": self.before,
                                 "desired": profile.VALUES, "file_before": None,
                                 "managed_content": profile.CONTENT})
        self.assertEqual(self.tool.rollback()["status"], "restored")
        self.assertFalse(self.tool.path(profile.STATE).exists())


if __name__ == "__main__":
    unittest.main()
