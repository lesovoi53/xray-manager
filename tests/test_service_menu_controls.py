"""Every installed, explicitly managed service has persistent-off menu control.

Uses the existing disposable systemd seam: never contacts the host manager.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("service_menu_fixture", ROOT / "tests/test_service_control.py")
control = fixture.control
installer = load("service_menu_installer", ROOT / "scripts/installer-state.py")


class ServiceMenuControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.systemd = fixture.Systemd(self.root)
        self.controller = control.Controller(self.root, self.systemd)

    def run_menu(self, answers):
        prompts = []
        answers = iter(answers)

        def answer(prompt):
            prompts.append(prompt)
            return next(answers)

        output = io.StringIO()
        with mock.patch("builtins.input", side_effect=answer), contextlib.redirect_stdout(output):
            control.unit_menu(self.controller)
        self.assertIsNone(next(answers, None), "The menu left expected input unused")
        return prompts, output.getvalue()

    def test_main_screen_groups_protocols_hides_empty_slots_and_never_mutates(self):
        self.systemd.units['snell6@1.service']['ActiveState']='active'
        for n in range(2,9):self.systemd.units[f'snell6@{n}.service']['ActiveState']='inactive'
        rows=control.menu_entries(self.controller)
        self.assertEqual(sum(label.startswith('Snell —') for label,_ in rows),1)
        shown=[u for _,units in rows for u in units]
        self.assertIn('snell6@1.service',shown)
        self.assertNotIn('snell6@2.service',shown)
        self.assertFalse(any('enabled' in label or 'inactive' in label or 'openflux@' in label for label,_ in rows))
        with mock.patch.object(self.controller,'change') as change, mock.patch('builtins.input',return_value='0'),contextlib.redirect_stdout(io.StringIO()):
            control.menu(self.controller)
        change.assert_not_called()

    def test_every_available_unit_has_clear_permanent_off_and_dispatches_it(self):
        answers = []
        for index, unit in enumerate(control.UNITS, 1):
            answers.extend((str(index), "3"))
            if unit == "fail2ban.service":
                answers.append("y")
        answers.append("0")
        with mock.patch.object(self.controller, "change", wraps=self.controller.change) as change:
            prompts, output = self.run_menu(answers)
        self.assertEqual(change.call_args_list, [mock.call("off", unit) for unit in control.UNITS])
        actions = [prompt for prompt in prompts if "Действие:" in prompt]
        self.assertEqual(len(actions), len(control.UNITS))
        self.assertTrue(all("[3] Выключить постоянно" in prompt for prompt in actions))
        self.assertNotIn("Ошибка управления службой", output)
        # Verify the menu dispatch reaches persistent policy, not only a stop.
        fresh = control.Controller(self.root, self.systemd)
        for unit in control.UNITS:
            with self.subTest(unit=unit):
                status = fresh.status(unit)
                self.assertTrue(status["off"])
                self.assertEqual(status["ActiveState"], "inactive")
                self.assertEqual(status["UnitFileState"], "disabled")
                self.assertFalse(fresh.allowed(unit))
                self.assertTrue(fresh.markers(unit)[0].exists())
                self.assertIn(("systemctl", "stop", unit), self.systemd.calls)
                self.assertIn(("systemctl", "disable", unit), self.systemd.calls)
                self.assertNotIn(("systemctl", "enable", unit), self.systemd.calls)

    def test_filtering_uninstalled_units_keeps_indices_and_masked_off_control(self):
        for state in self.systemd.units.values():
            state["LoadState"] = "not-found"
        selected = ("snell.service", "openflux@8.service", "snell6@8.service", "tuna-healthcheck.timer")
        for unit in selected:
            self.systemd.units[unit]["LoadState"] = "masked"
            self.systemd.units[unit]["UnitFileState"] = "masked"
        ordered = [unit for unit in control.UNITS if unit in selected]
        answers = [part for index in range(1, len(ordered) + 1) for part in (str(index), "3")] + ["0"]
        with mock.patch.object(self.controller, "change", wraps=self.controller.change) as change:
            _, output = self.run_menu(answers)
        self.assertEqual(change.call_args_list, [mock.call("off", unit) for unit in ordered])
        self.assertNotIn("mita.service:", output)
        self.assertFalse(any(call[0] == "systemctl" and call[1] == "unmask" for call in self.systemd.calls))

    def test_manual_stop_and_autostart_off_remain_distinct_actions(self):
        index = str(control.UNITS.index("snell.service") + 1)
        with mock.patch.object(self.controller, "change", wraps=self.controller.change) as change:
            self.run_menu([index, "2", index, "6", "0"])
        self.assertEqual(change.call_args_list, [mock.call("stop", "snell.service"),
                                                mock.call("autostart-off", "snell.service")])
        self.assertFalse(self.controller.status("snell.service")["off"])
        self.assertTrue(self.controller.status("snell.service")["stopped"])

    def test_fail2ban_permanent_off_requires_explicit_informed_confirmation(self):
        index = str(control.UNITS.index("fail2ban.service") + 1)
        for answer in ("", "n", "no", "нет"):
            with self.subTest(answer=answer), mock.patch.object(self.controller, "change") as change:
                prompts, _ = self.run_menu([index, "3", answer, "0"])
                change.assert_not_called()
                self.assertTrue(any("отключит защиту от перебора паролей" in prompt for prompt in prompts))
        with mock.patch.object(self.controller, "change", wraps=self.controller.change) as change:
            self.run_menu([index, "3", "да", "0"])
            change.assert_called_once_with("off", "fail2ban.service")
        self.assertTrue(self.controller.status("fail2ban.service")["off"])

    def test_allowlist_covers_installer_units_shipped_templates_and_legacy_protocols(self):
        expected = set(installer.SERVICES)
        for directory in (ROOT / "systemd", ROOT / "tuna-sub-server"):
            for path in directory.iterdir():
                if path.suffix not in (".service", ".timer"):
                    continue
                if "@." in path.name:
                    expected.update(path.name.replace("@.", "@%d." % slot) for slot in range(1, 9))
                else:
                    expected.add(path.name)
        for name in ("install.sh", "bin/x-manager", "tuna-sub-server/install-sub-server.sh"):
            source = (ROOT / name).read_text(encoding="utf-8")
            for unit in re.findall(r"/etc/systemd/system/([A-Za-z0-9_-]+(?:@[0-9]*)?\.(?:service|timer))", source):
                if "@." in unit:
                    expected.update(unit.replace("@.", "@%d." % slot) for slot in range(1, 9))
                else:
                    expected.add(unit)
        expected.update(name + ".service" for name in (
            "wdtt", "csqtt", "cottendns", "masterdns", "mita", "snell", "x-ui",
            "xray", "sing-box", "caddy", "vpn-watchdog", "tuna-watchdog", "fail2ban"))
        expected.update(("vpn-watchdog.timer", "tuna-watchdog.timer", "tuna-healthcheck.timer", "volga-cookies.timer"))
        # Reboot is governed by reboot-schedule.py, never generic service actions.
        scheduled_reboot = {'x-manager-reboot.service', 'x-manager-reboot.timer'}
        self.assertFalse(scheduled_reboot & set(control.UNITS))
        expected -= scheduled_reboot
        self.assertFalse(expected - set(control.UNITS), "Missing managed units: " + repr(sorted(expected - set(control.UNITS))))
        self.assertEqual(len(control.UNITS), len(set(control.UNITS)))
        self.assertIn("fail2ban.service", installer.SERVICES)
        self.assertIn("/etc/systemd/system/fail2ban.service.d/95-tuna-service-control.conf", installer.PATHS)

    def test_ssh_and_unrelated_system_units_are_never_exposed_or_accepted(self):
        _, output = self.run_menu(["0"])
        for unit in ("ssh.service", "sshd.service", "sshd@root.service", "NetworkManager.service",
                     "dbus.service", "systemd-networkd.service", "openflux@9.service", "snell6@9.service"):
            with self.subTest(unit=unit):
                self.assertNotIn(unit, control.UNITS)
                self.assertNotIn(unit, output)
                with self.assertRaises(ValueError):
                    control.canonical(unit)

    @unittest.skipUnless(os.name == "posix", "Bash fixture paths require a Linux runtime")
    def test_snell_v5_settings_are_named_and_point_to_separate_v6_menu(self):
        script = r'''
. "$1"
xm_header() { printf '%s\n' "$1"; }
get_snell_status() { echo active; }
xm_choose_action menu_snell selected
test "$selected" = 0
'''
        result = subprocess.run(["bash", "-c", script, "bash", str(ROOT / "scripts/menu-v2.sh")],
                                input="2\n0\n0\n", text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Snell v5 / Настройки", result.stdout)
        self.assertIn("Snell v6: настройки находятся в разделе Snell → [2]", result.stdout)
        self.assertIn("HTTP-обфускация", result.stdout)
        self.assertNotIn("Snell v4", result.stdout)
        source = (ROOT / "scripts/menu-v2.sh").read_text(encoding="utf-8")
        self.assertIn("[2] Snell — v5: %b | v6: %s", source)
        self.assertNotIn("[9] Snell v6", source)

    @unittest.skipUnless(os.name == "posix", "Bash fixture paths require a Linux runtime")
    def test_snell_selector_routes_old_new_and_back_without_service_changes(self):
        script = r'''
. "$1"
xm_header() { printf '%s\n' "$1"; }
get_snell_status() { echo active; }
menu_snell() { echo OLD_SETTINGS; }
python3() { test "${1##*/}" = snell6-endpoints.py && test "$2" = menu && echo NEW_SETTINGS; }
systemctl() { echo UNEXPECTED_SERVICE_MUTATION; return 99; }
xm_snell_menu
'''
        for answers, expected in (("1\n0\n", "OLD_SETTINGS"), ("2\n0\n", "NEW_SETTINGS"), ("0\n", None)):
            with self.subTest(expected=expected):
                result = subprocess.run(["bash", "-c", script, "bash", str(ROOT / "scripts/menu-v2.sh")],
                                        input=answers, text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Snell — версия сервера", result.stdout)
                self.assertNotIn("UNEXPECTED_SERVICE_MUTATION", result.stdout)
                for label in ("OLD_SETTINGS", "NEW_SETTINGS"):
                    self.assertEqual(label in result.stdout, label == expected)
        source = (ROOT / "scripts/menu-v2.sh").read_text(encoding="utf-8")
        self.assertIn("2) xm_snell_menu;;", source)

    @unittest.skipUnless(os.name == "posix", "Bash fixture paths require Linux")
    def test_own_service_buttons_target_only_the_current_service(self):
        script = r'''
. "$1"
xm_header() { :; }; xm_pause() { :; }; xm_confirm() { return 0; }
get_mieru_status() { echo active; }; get_snell_status() { echo active; }
get_wdavtunnel_status() { echo active; }; get_wdavtunnel_provider_label() { echo local; }
get_sub_server_status() { echo active; }
python3() { printf 'ACTION:%s:%s\n' "$2" "$3"; }
xm_choose_action "$2" selected
test "$selected" = 0
'''
        cases = (("menu_mieru", "mita.service", "90", "91"), ("menu_snell", "snell.service", "90", "91"),
                 ("menu_webdav_tunnel", "webdav-tunnel.service", "90", "91"),
                 ("menu_subscriptions", "tuna-subscriptions.service", "90", "91"),
                 ("menu_wdtt", "wdtt.service", "90", "91"), ("menu_csqtt", "csqtt.service", "90", "91"),
                 ("menu_dns", "cottendns.service", "90", "91"), ("menu_dns", "masterdns.service", "92", "93"))
        for menu, unit, on, off in cases:
            with self.subTest(menu=menu, unit=unit):
                result = subprocess.run(["bash", "-c", script, "bash", str(ROOT / "scripts/menu-v2.sh"), menu],
                                        input=on + "\n" + off + "\n0\n", text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([line for line in result.stdout.splitlines() if line.startswith("ACTION:")],
                                 ["ACTION:switch:--version" if unit == "snell.service" else "ACTION:on:" + unit,
                                  "ACTION:off:" + unit])
                self.assertIn("Выключить", result.stdout)

    @unittest.skipUnless(os.name == "posix", "Bash fixture paths require Linux")
    def test_openflux_own_channel_and_bulk_controls_have_exact_scope(self):
        script = r'''
. "$1"
xm_header() { :; }; xm_pause() { :; }; xm_confirm() { return 0; }
get_openflux_channel_prop() { case "$1" in 2|7) echo configured;; 3) echo '   ';; *) echo '';; esac; }
python3() { printf 'ACTION:%s:%s\n' "$2" "$3"; }
case "$2" in one) xm_openflux_channel_actions 3 || :;; on) xm_openflux_all_action on;; off) xm_openflux_all_action off;; esac
'''
        for mode, answers, expected in (
                ("one", "90\n91\n0\n", ["ACTION:on:openflux@3.service", "ACTION:off:openflux@3.service"]),
                ("on", "", ["ACTION:on:openflux@2.service", "ACTION:on:openflux@7.service"]),
                ("off", "", ["ACTION:off:openflux@%d.service" % i for i in range(1, 9)])):
            with self.subTest(mode=mode):
                result = subprocess.run(["bash", "-c", script, "bash", str(ROOT / "scripts/menu-v2.sh"), mode],
                                        input=answers, text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([line for line in result.stdout.splitlines() if line.startswith("ACTION:")], expected)
        failure_script = script.replace("python3() { printf", "python3() { [ \"$3\" != openflux@4.service ] || return 1; printf")
        result = subprocess.run(["bash", "-c", failure_script, "bash", str(ROOT / "scripts/menu-v2.sh"), "off"],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Не все каналы обработаны", result.stderr)
        self.assertIn("ACTION:off:openflux@8.service", result.stdout)

    @unittest.skipUnless(os.name == "posix", "Endpoint filesystem fixture requires Linux")
    def test_snell6_menu_off_on_changes_only_selected_slot_and_preserves_config(self):
        endpoints = load("service_menu_snell6_fixture", ROOT / "tests/test_snell6_endpoints.py")
        case = endpoints.Endpoints()
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.create(slot=2)
        case.create(slot=3)
        lifecycle_system = fixture.Systemd(case.root)
        for unit, state in case.system.states.items():
            lifecycle_system.units[unit].update(state)
        case.manager.run = lifecycle_system
        before = {slot: case.snapshot(slot) for slot in (2, 3)}
        with mock.patch("builtins.input", side_effect=["2", "5", "1", "0", "0"]), contextlib.redirect_stdout(io.StringIO()):
            endpoints.snell6.menu(case.manager)
        self.assertTrue(case.manager.lifecycle().status("snell6@3.service")["off"])
        self.assertFalse(case.manager.lifecycle().status("snell6@2.service")["off"])
        original_loader = endpoints.snell6.load_helper
        switch = mock.Mock()
        switch.Controller.return_value.switch.return_value = {"changed": True}
        def loader(name):
            return switch if name == "snell-switch" else original_loader(name)
        with mock.patch.object(endpoints.snell6, "load_helper", side_effect=loader), \
                mock.patch("builtins.input", side_effect=["2", "4", "1", "0", "0"]), \
                contextlib.redirect_stdout(io.StringIO()):
            endpoints.snell6.menu(case.manager)
        switch.Controller.return_value.switch.assert_called_once_with(6, "3")
        for slot in (2, 3):
            self.assertEqual(case.snapshot(slot), before[slot])


if __name__ == "__main__":
    unittest.main()
