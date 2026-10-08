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
        if args[0] == "modprobe":
            if args[1] == "tcp_bbr":
                self.write("/proc/sys/net/ipv4/tcp_available_congestion_control", "reno cubic bbr")
            elif args[1] == "nf_conntrack":
                self.write("/proc/sys/net/netfilter/nf_conntrack_max", "32768")
            return ""
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

    def adaptive_fixture(self, ram_kib=2 * 1024**2):
        self.write('/proc/meminfo', 'MemTotal: %d kB\nSwapTotal: 999999999 kB\n' % ram_kib)
        self.write('/proc/self/cgroup', '0::/test\n')
        for key, value in profile.ADAPTIVE.items():
            if key in profile.VALUES:
                continue
            initial = '4096\t87380\t1048576' if key == 'net.ipv4.tcp_rmem' else (
                '4096 16384 1048576' if key == 'net.ipv4.tcp_wmem' else '1024')
            self.write('/proc/sys/' + key.replace('.', '/'), initial)

    def test_adaptive_tiers_cgroup_ancestors_and_unlimited_without_swap(self):
        for mib, tier, buf, ct, backlog in ((512, '<1 GiB', 4, 65536, 4096),
                    (1024, '1–<2 GiB', 8, 131072, 8192), (2048, '2–<4 GiB', 16, 262144, 16384),
                    (4096, '>=4 GiB', 16, 524288, 16384)):
            self.adaptive_fixture(mib * 1024)
            m = self.tool.memory()
            self.assertEqual((m['tier'], m['buffer_bytes'], m['conntrack_max'], m['backlog']),
                             (tier, buf * 1024**2, ct, backlog))
        self.write('/sys/fs/cgroup/memory.max', str(1536 * 1024**2))
        self.write('/sys/fs/cgroup/test/memory.max', 'max')
        self.assertEqual(self.tool.memory()['effective_bytes'], 1536 * 1024**2)
        self.write('/proc/self/cgroup', '3:memory:/test\n')
        self.tool.path('/sys/fs/cgroup/memory.max').unlink()
        self.write('/sys/fs/cgroup/memory/test/memory.limit_in_bytes', str(512 * 1024**2))
        self.assertEqual(self.tool.memory()['effective_bytes'], 512 * 1024**2)

    def test_adaptive_plan_read_only_prepare_and_repeat_preserve_original_snapshot(self):
        self.adaptive_fixture()
        self.write('/proc/sys/net/ipv4/tcp_available_congestion_control', 'cubic')
        self.tool.path('/proc/sys/net/netfilter/nf_conntrack_max').unlink()
        plan = self.tool.plan(adaptive=True)
        self.assertFalse(plan['ready'])
        self.assertTrue(plan['preflight_ready'])
        self.assertIn('tcp_bbr', plan['needs_prepare'])
        self.assertEqual(self.calls, [])
        self.tool.prepare(adaptive=True)
        self.assertEqual(self.tool.read(profile.MODULES), profile.MODULE_CONTENT)
        before = self.tool.effective(profile.MANAGED_KEYS)
        self.assertEqual(self.tool.apply(adaptive=True)['status'], 'applied')
        original = self.tool.read(profile.STATE)
        self.calls.clear()
        self.assertEqual(self.tool.apply(adaptive=True)['status'], 'unchanged')
        self.assertEqual(self.tool.read(profile.STATE), original)
        self.assertEqual(self.calls, [])
        self.tool.rollback()
        self.assertEqual(self.tool.effective(profile.MANAGED_KEYS), before)
        self.assertFalse(self.tool.path(profile.MODULES).exists())

    def test_adaptive_retains_larger_buffers_and_triple_defaults_and_reports_all(self):
        self.adaptive_fixture(512 * 1024)
        self.write('/proc/sys/net/core/rmem_max', '33554432')
        self.write('/proc/sys/net/netfilter/nf_conntrack_max', '1048576')
        self.write('/proc/sys/net/ipv4/tcp_rmem', '4096 87380 33554432')
        plan = self.tool.plan(adaptive=True)
        self.assertEqual(plan['desired']['net.core.rmem_max'], '33554432')
        self.assertEqual(plan['desired'][profile.CT + 'max'], '1048576')
        self.assertEqual(plan['desired']['net.ipv4.tcp_rmem'], '4096 87380 33554432')
        text = profile.human_report(plan)
        self.assertIn('512 MiB', text)
        self.assertTrue(all(key in text for key in plan['desired']))
        self.assertGreaterEqual(len(plan['warnings']), 3)

    def test_adaptive_failed_write_restores_runtime_files_and_original_modules_file(self):
        self.adaptive_fixture()
        self.write(profile.MODULES, profile.HEADER + '# previous\n')
        before = self.tool.effective(profile.MANAGED_KEYS)
        self.tool.prepare(adaptive=True)
        self.fail_once = '7200'
        with self.assertRaisesRegex(RuntimeError, 'original runtime and file restored'):
            self.tool.apply(adaptive=True)
        self.assertEqual(self.tool.effective(profile.MANAGED_KEYS), before)
        self.assertEqual(self.tool.read(profile.MODULES), profile.HEADER + '# previous\n')
        self.assertFalse(self.tool.path(profile.CONFIG).exists())
        self.assertFalse(self.tool.path(profile.STATE).exists())

    def test_adaptive_unsupported_optional_keys_and_admin_conflicts(self):
        self.adaptive_fixture()
        self.tool.path('/proc/sys/' + next(iter(profile.TIMEOUTS)).replace('.', '/')).unlink()
        plan = self.tool.plan(adaptive=True)
        self.assertTrue(plan['preflight_ready'])
        self.assertEqual(len(plan['warnings']), 1)
        self.tool.path('/proc/sys/net/ipv4/tcp_keepalive_time').unlink()
        self.assertFalse(self.tool.plan(adaptive=True)['preflight_ready'])
        self.write('/proc/sys/net/ipv4/tcp_keepalive_time', '1024')
        self.write('/etc/sysctl.d/99-admin.conf', 'net.ipv4.tcp_rmem = 4096 87380 99999999\n')
        self.assertFalse(self.tool.plan(adaptive=True)['preflight_ready'])
        self.assertEqual(self.calls, [])

    def test_adaptive_prepared_rollback_and_admin_runtime_change(self):
        self.adaptive_fixture()
        self.tool.prepare(adaptive=True)
        self.tool.rollback()
        self.assertFalse(self.tool.path(profile.MODULES).exists())
        self.tool.prepare(adaptive=True)
        self.tool.apply(adaptive=True)
        self.write('/proc/sys/net/core/rmem_max', '99999999')
        with self.assertRaisesRegex(ValueError, 'Runtime changed'):
            self.tool.apply(adaptive=True)
        with self.assertRaisesRegex(ValueError, 'Runtime changed'):
            self.tool.rollback()

    def test_adaptive_rejects_invalid_tcp_triples_and_legacy_snapshot(self):
        self.adaptive_fixture()
        self.tool.apply()
        self.assertFalse(self.tool.plan(adaptive=True)['preflight_ready'])
        self.tool.rollback()
        for value in ('1 2', '0 2 3', '5 4 3', '1 2 bad'):
            self.write('/proc/sys/net/ipv4/tcp_rmem', value)
            with self.assertRaisesRegex(ValueError, 'Unexpected effective'):
                self.tool.plan(adaptive=True)


if __name__ == "__main__":
    unittest.main()
