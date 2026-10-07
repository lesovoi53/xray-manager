import contextlib
import io
import sys
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("resources", ROOT / "scripts/openflux-resources.py")
resources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resources)


class ResourceBudgets(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write("proc/meminfo", "MemTotal: 4194304 kB\nMemAvailable: 3145728 kB\nSwapTotal: 8388608 kB\nSwapFree: 8388608 kB\n")
        self.write("etc/openflux/instances/1.env", "URL='https://fixture.invalid/private'\nENCRYPTION_KEY=synthetic-secret\n")

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def plan(self, **kwargs):
        return resources.build_plan(self.root, **kwargs)

    def test_matrix_respects_aggregate_reserves_and_never_counts_swap(self):
        for ram_mib in (512, 1024, 3072, 4096, 16384):
            for count in range(1, 9):
                self.write("proc/meminfo", f"MemTotal: {ram_mib * 1024} kB\nSwapTotal: 8388608 kB\n")
                with patch.object(resources, "configured_channels", return_value={str(i) for i in range(1, count + 1)}):
                    plan = self.plan()
                self.assertEqual(len(plan["channels"]), count)
                allocation = plan["recommended_mib"]
                self.assertEqual(sum(allocation.values()), plan["total_go_budget_mib"])
                remainder = max(0, ram_mib - plan["reserve_os_mib"] - plan["reserve_other_mib"])
                self.assertLessEqual(sum(allocation.values()), remainder)
                self.assertLessEqual(max(allocation.values()) - min(allocation.values()), 1)
                self.assertEqual(plan["can_apply"], min(allocation.values()) >= 64)

    def test_cgroup_limit_and_parents_limit_hardware_budget(self):
        self.write("proc/self/cgroup", "0::/tenant/work\n")
        self.write("sys/fs/cgroup/memory.max", "max\n")
        self.write("sys/fs/cgroup/tenant/memory.max", str(1536 * resources.MIB))
        self.write("sys/fs/cgroup/tenant/work/memory.max", str(2048 * resources.MIB))
        self.assertEqual(self.plan()["memory"]["effective_bytes"], 1536 * resources.MIB)

    def test_report_is_read_only_and_does_not_emit_saved_secrets(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        plan = self.plan()
        self.assertNotIn("synthetic-secret", json.dumps(plan))
        self.assertNotIn("fixture.invalid", json.dumps(plan))
        self.assertEqual(before, {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
        self.assertFalse((self.root / resources.STATE).exists())

    def test_active_and_previously_managed_channels_stay_in_aggregate(self):
        self.write("etc/openflux/instances/2.env", "URL=''\n")
        self.write("etc/openflux/resources.conf", "3=200MiB\n")
        with patch.object(resources, "systemd_channels", return_value=({"4": {"active_state": "active"}}, [])):
            plan = self.plan()
        self.assertEqual(plan["channels"], ["1", "3", "4"])
        self.assertEqual(plan["configured_channels"], ["1"])

    def test_empty_instance_one_does_not_fallback_to_legacy(self):
        self.write("etc/openflux/instances/1.env", "URL=''\n")
        self.write("etc/openflux/openflux.env", "URL=old-value\n")
        self.assertEqual(self.plan()["channels"], [])

    def test_user_overrides_and_impossible_budgets(self):
        plan = self.plan(total_mib=1200, reserve_os_mib=512, reserve_other_mib=768)
        self.assertEqual(plan["recommended_mib"], {"1": 1200})
        with self.assertRaises(ValueError):
            self.plan(total_mib=3000, reserve_os_mib=512, reserve_other_mib=768)
        with self.assertRaises(ValueError):
            self.plan(reserve_other_mib=-1)
        with self.assertRaises(ValueError):
            resources.apply_plan(self.root, self.plan(total_mib=63))

    def test_spare_ram_does_not_automatically_raise_existing_target(self):
        self.assertEqual(self.plan()["recommended_mib"], {"1": 150})
        self.write("etc/openflux/instances/1.env", "URL=fixture\nGOMEMLIMIT=180MiB\n")
        self.assertEqual(self.plan()["recommended_mib"], {"1": 180})
        self.assertEqual(self.plan(total_mib=900)["recommended_mib"], {"1": 900})

    def test_apply_repeat_and_rollback_preserve_unrelated_bytes(self):
        channel = self.root / "etc/openflux/instances/1.env"
        before = channel.read_bytes()
        result = resources.apply_plan(self.root, self.plan(total_mib=200))
        self.assertTrue(result["changed"])
        self.assertFalse(result["restart_performed"])
        self.assertEqual(resources.parse_limits((self.root / resources.CONFIG).read_text()), {"1": 200})
        self.assertFalse(resources.apply_plan(self.root, self.plan(total_mib=200))["changed"])
        self.assertTrue(resources.rollback(self.root, result["snapshot_id"])["changed"])
        self.assertFalse((self.root / resources.CONFIG).exists())
        self.assertFalse(resources.rollback(self.root, result["snapshot_id"])["changed"])
        self.assertEqual(channel.read_bytes(), before)

    def test_update_rollback_exact_content_and_mode(self):
        config = self.write("etc/openflux/resources.conf", "# old exact bytes\n1=150MiB\n")
        config.chmod(0o640)
        result = resources.apply_plan(self.root, self.plan(total_mib=300))
        resources.rollback(self.root, result["snapshot_id"])
        self.assertEqual(config.read_text(), "# old exact bytes\n1=150MiB\n")
        self.assertEqual(config.stat().st_mode & 0o777, 0o640)

    def test_rollback_refuses_newer_edits_and_invalid_id(self):
        result = resources.apply_plan(self.root, self.plan(total_mib=300))
        config = self.write("etc/openflux/resources.conf", "1=999MiB\n")
        with self.assertRaisesRegex(ValueError, "newer edits"):
            resources.rollback(self.root, result["snapshot_id"])
        self.assertEqual(config.read_text(), "1=999MiB\n")
        with self.assertRaisesRegex(ValueError, "invalid snapshot"):
            resources.rollback(self.root, "../../outside")

    def test_failure_before_atomic_replace_leaves_old_budget(self):
        config = self.write("etc/openflux/resources.conf", "1=150MiB\n")
        replace = os.replace
        def fail_config(source, target):
            if target == config:
                raise OSError("simulated full filesystem")
            replace(source, target)
        with patch.object(resources.os, "replace", side_effect=fail_config):
            with self.assertRaises(OSError):
                resources.apply_plan(self.root, self.plan(total_mib=300))
        self.assertEqual(config.read_text(), "1=150MiB\n")

    def test_stale_plan_refuses_changed_limits_or_channel_inventory(self):
        plan = self.plan(total_mib=200)
        self.write("etc/openflux/resources.conf", "1=250MiB\n")
        with self.assertRaisesRegex(ValueError, "changed after planning"):
            resources.apply_plan(self.root, plan)
        plan = self.plan(total_mib=200)
        self.write("etc/openflux/instances/2.env", "URL=new-channel\n")
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            resources.apply_plan(self.root, plan)

    def test_managed_file_never_accepts_shell_or_duplicate_values(self):
        for text in ("1=$(touch /tmp/unsafe)MiB\n", "1=100MiB\n1=200MiB\n", "9=100MiB\n", "1=-1MiB\n", "1=100MiB;true\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                resources.parse_limits(text)

    def test_mutations_refuse_symlink_destination(self):
        external = self.write("outside", "1=100MiB\n")
        (self.root / resources.CONFIG).symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symlink"):
            resources.apply_plan(self.root, self.plan(total_mib=200))
        self.assertEqual(external.read_text(), "1=100MiB\n")

    def test_auto_three_channels_repeat_manual_and_rollback(self):
        self.write("proc/meminfo", "MemTotal: 990208 kB\n")
        for channel in (2, 3):
            self.write(f"etc/openflux/instances/{channel}.env", "URL=fixture\n")
        before = (self.root / "etc/openflux/instances/1.env").read_bytes()
        first = resources.auto_apply(self.root)
        config = self.root / resources.CONFIG
        automatic = config.read_bytes()
        self.assertEqual(resources.parse_limits(config.read_text()), {"1": 114, "2": 114, "3": 113})
        self.assertFalse(resources.auto_apply(self.root)["changed"])
        self.assertEqual(len(list((self.root / resources.STATE).glob("*.json"))), 1)
        manual = resources.apply_plan(self.root, self.plan(total_mib=300))
        saved = config.read_bytes()
        self.assertFalse(resources.auto_apply(self.root)["changed"])
        self.assertEqual(config.read_bytes(), saved)
        resources.rollback(self.root, manual["snapshot_id"])
        self.assertEqual(config.read_bytes(), automatic)
        resources.rollback(self.root, first["snapshot_id"])
        self.assertFalse(config.exists())
        self.assertEqual((self.root / "etc/openflux/instances/1.env").read_bytes(), before)

    def test_auto_add_channel_and_insufficient_ram_preserve_previous(self):
        self.write("proc/meminfo", "MemTotal: 990208 kB\n")
        resources.auto_apply(self.root)
        for channel in (2, 3):
            self.write(f"etc/openflux/instances/{channel}.env", "URL=fixture\n")
        resources.auto_apply(self.root)
        config = self.root / resources.CONFIG
        self.assertEqual(resources.parse_limits(config.read_text()), {"1": 114, "2": 114, "3": 113})
        before = config.read_bytes()
        self.write("proc/meminfo", "MemTotal: 524288 kB\n")
        with self.assertRaisesRegex(ValueError, "safe channel budget"):
            resources.auto_apply(self.root)
        self.assertEqual(config.read_bytes(), before)

    def test_auto_runtime_inspection_failure_does_not_write(self):
        with patch.object(resources, "systemd_channels", return_value=({}, ["systemd runtime memory inspection unavailable"])):
            with self.assertRaisesRegex(ValueError, "systemd"):
                resources.auto_apply(self.root)
        self.assertFalse((self.root / resources.CONFIG).exists())

    def test_auto_rejects_ignored_options(self):
        for options in (["unexpected"], ["--total-mib", "200"], ["--reserve-os-mib", "0"]):
            with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                resources.main(["auto", "--root", str(self.root), *options])
        self.assertFalse((self.root / resources.CONFIG).exists())

    def test_concurrent_auto_one_backup_and_complete_file(self):
        command = [sys.executable, str(ROOT / "scripts/openflux-resources.py"), "auto", "--root", str(self.root), "--json"]
        processes = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(3)]
        results = []
        for process in processes:
            out, err = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, err)
            results.append(json.loads(out))
        self.assertEqual(sum(row["changed"] for row in results), 1)
        self.assertEqual(resources.parse_limits((self.root / resources.CONFIG).read_text()), {"1": 150})
        self.assertEqual(len(list((self.root / resources.STATE).glob("*.json"))), 1)

    def test_human_report_shows_pending_limit_and_runtime_failure(self):
        self.write("etc/openflux/resources.conf", "# X-Manager automatic Go soft budgets.\n1=114MiB\n")
        runtime = {"1": {"active_state": "active", "runtime_gomemlimit": "150MiB", "VmRSSBytes": 32 * resources.MIB}}
        output = io.StringIO()
        with patch.object(resources, "systemd_channels", return_value=(runtime, [])), contextlib.redirect_stdout(output):
            self.assertEqual(resources.main(["report", "--root", str(self.root)]), 0)
        self.assertIn("32.0 МиБ", output.getvalue())
        self.assertIn("после следующего запуска", output.getvalue())
        self.assertNotIn("Применить:", output.getvalue())
        output = io.StringIO()
        with patch.object(resources, "systemd_channels", return_value=({}, ["systemd runtime memory inspection unavailable"])), contextlib.redirect_stdout(output):
            resources.main(["report", "--root", str(self.root)])
        self.assertIn("Не удалось прочитать состояние systemd", output.getvalue())

    def test_runner_effective_default_override_and_rejects_shell(self):
        binary = self.write("openflux", "#!/bin/sh\nprintf 'LIMIT=%s\\n' \"$GOMEMLIMIT\"\n")
        binary.chmod(0o755)
        self.write("etc/openflux/instances/1.env", "TRANSPORT=fixture\nURL=fixture\nDEBUG=0\nGOMEMLIMIT=180MiB\n")
        runner = (ROOT / "scripts/openflux-runner.sh").read_text().replace("/etc/", str(self.root / "etc") + "/").replace("/usr/local/bin/openflux", str(binary))
        def run():
            return subprocess.run(["bash", "-c", runner, "runner", "1"], capture_output=True, text=True)
        self.assertIn("LIMIT=180MiB", run().stdout)
        resources.apply_plan(self.root, self.plan(total_mib=320))
        self.assertIn("LIMIT=320MiB", run().stdout)
        self.write("etc/openflux/instances/2.env", "TRANSPORT=fixture\nURL=fixture\nDEBUG=0\n")
        missing = subprocess.run(["bash", "-c", runner, "runner", "2"], capture_output=True, text=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("No managed OpenFlux memory budget", missing.stderr)
        self.assertNotIn("LIMIT=", missing.stdout)
        marker = self.root / "must-not-exist"
        self.write("etc/openflux/resources.conf", f"1=$(touch {marker})MiB\n")
        invalid = run()
        self.assertNotEqual(invalid.returncode, 0)
        self.assertIn("Invalid OpenFlux resource budget", invalid.stderr)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
