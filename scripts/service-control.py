#!/usr/bin/env python3
"""Explicit lifecycle intent for X-Manager units, independent of unit contents.

off: persistent inhibit, disabled autostart, stop. on: clear inhibit, enable, start.
stop: inhibit until explicit start or reboot. autostart-off does not stop a unit.
No mask/unmask: locally installed /etc units and administrator masks are preserved.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

SERVICES = ["tuna-subscriptions", "webdav-tunnel", "snell", "mita", "wdtt",
            "wdtt-tproxy", "csqtt", "masterdns", "cottendns", "x-ui", "volga-cookies",
            "xray", "sing-box", "caddy", "vpn-watchdog", "tuna-watchdog", "tuna-healthcheck", "fail2ban"]
UNITS = tuple([name + ".service" for name in SERVICES]
              + ["openflux@%d.service" % i for i in range(1, 9)]
              + ["snell6@%d.service" % i for i in range(1, 9)]
              + ["volga-cookies.timer", "vpn-watchdog.timer", "tuna-watchdog.timer", "tuna-healthcheck.timer"])
EXTERNAL_WATCHDOGS = ("vpn-watchdog.service", "vpn-watchdog.timer",
                      "tuna-watchdog.service", "tuna-watchdog.timer")
STATE_DIR = "/etc/x-manager/service-control"
RUNTIME_DIR = "/run/x-manager/service-control"
DROPIN = "95-tuna-service-control.conf"
HEADER = "# Managed by X-Manager service-control.py; use its lifecycle commands.\n"
SNELL_UNITS = ("snell.service",) + tuple("snell6@%d.service" % i for i in range(1, 9))


def canonical(unit):
    if not unit:
        raise ValueError("Нужно указать службу")
    name = unit if unit.endswith((".service", ".timer")) else unit + ".service"
    if name not in UNITS:
        raise ValueError("Служба вне явного списка X-Manager: " + unit)
    return name


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(" ".join(args) + ": " + (result.stderr.strip() or result.stdout.strip()))
    return result.stdout.strip()


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Subscription service may stat inhibit markers; file contents stay private.
    if path.parent.name in ("off", "stopped") and path.parent.parent.name == "service-control":
        path.parent.chmod(0o711)
    if path.is_symlink():
        raise ValueError("Refusing to replace symlink: " + str(path))
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Controller:
    def __init__(self, root=Path("/"), run=command):
        self.root = Path(root)
        self.run = run
        self.state_path = self.path(STATE_DIR + "/state.json")

    def path(self, absolute):
        return self.root / absolute.lstrip("/")

    def ctl(self, *args):
        return self.run("systemctl", *args)

    @contextmanager
    def lock(self):
        directory = self.path(RUNTIME_DIR)
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o711)
        with (directory / "lock").open("a") as stream:
            if os.name == "posix":
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def read(self):
        if not self.state_path.exists():
            return {"version": 1, "units": {}}
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        if (not isinstance(state, dict) or state.get("version") != 1
                or not isinstance(state.get("units"), dict)):
            raise ValueError("Invalid lifecycle state; refusing to reset user intent")
        for unit, intent in state["units"].items():
            if (canonical(unit) != unit or not isinstance(intent, dict)
                    or type(intent.get("off")) is not bool
                    or intent.get("autostart") is not None and type(intent["autostart"]) is not bool):
                raise ValueError("Invalid lifecycle entry: " + unit)
        return state

    def save(self, state):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.parent.chmod(0o711)
        atomic_write(self.state_path, json.dumps(state, sort_keys=True, indent=2) + "\n")

    def markers(self, unit):
        return (self.path(STATE_DIR + "/off/" + unit),
                self.path(RUNTIME_DIR + "/stopped/" + unit))

    def show(self, unit):
        output = self.ctl("show", unit, "--property=LoadState,ActiveState,UnitFileState,Type,Restart,Result")
        return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)

    def allowed(self, unit, enable=False):
        unit = canonical(unit)
        intent = self.read()["units"].get(unit, {})
        permanent, stopped = self.markers(unit)
        if intent.get("off") or permanent.exists():
            return False
        try:
            self.check_snell_selection(unit)
        except (ValueError, OSError, RuntimeError):
            return False
        if enable:
            return intent.get("autostart") is not False
        return not stopped.exists()

    def check_snell_selection(self, unit):
        """All public activation paths respect the single selected Snell server."""
        if unit not in SNELL_UNITS or getattr(self, "_snell_switch_authorized", False):
            return
        marker = self.path("/etc/x-manager/snell-active.json")
        if marker.exists() or marker.is_symlink():
            # Share marker validation with the switch transaction. Import here
            # avoids a module-level cycle: snell-switch itself uses Controller.
            spec = importlib.util.spec_from_file_location(
                "snell_selection_guard", Path(__file__).with_name("snell-switch.py"))
            selection = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(selection)
            chosen = selection.read_selection(self.root)
            if chosen is None:
                raise ValueError("Snell selection changed; retry using snell-switch")
            if chosen["unit"] != unit:
                raise ValueError("Эта версия или слот Snell не выбраны; используйте snell-switch")
            if chosen["version"] == 6:
                endpoint = self.path("/etc/snell6/endpoints/" + chosen["slot"] + "/endpoint.json")
                if endpoint.is_symlink():
                    raise ValueError("Endpoint identity must not be a symlink; use snell-switch")
                value = json.loads(endpoint.read_text(encoding="utf-8"))
                if not isinstance(value, dict) or value.get("endpoint_id") != chosen["endpoint_id"]:
                    raise ValueError("Selected Snell endpoint identity changed; use snell-switch")
        # A missing marker supports existing installations only when no other
        # version/slot can already run or start at boot. Never silently stop it.
        for other in SNELL_UNITS:
            if other == unit:
                continue
            live = self.show(other)
            if live.get("LoadState") not in ("loaded", "masked"):
                continue
            if (live.get("ActiveState") in ("active", "activating", "reloading", "deactivating")
                    or live.get("UnitFileState") in ("enabled", "enabled-runtime")):
                raise ValueError("Другая версия или слот Snell активны либо включены; используйте snell-switch")

    def dropin(self, unit):
        return self.path("/etc/systemd/system/" + unit + ".d/" + DROPIN)

    def check_owned(self, unit):
        path = self.dropin(unit)
        if path.is_symlink() or path.exists() and not path.read_text(encoding="utf-8").startswith(HEADER):
            raise ValueError("Lifecycle override has foreign contents: " + str(path))

    def guard(self, unit, off):
        self.check_owned(unit)
        content = (HEADER + "[Unit]\nConditionPathExists=!" + STATE_DIR + "/off/" + unit
                   + "\nConditionPathExists=!" + RUNTIME_DIR + "/stopped/" + unit + "\n")
        if off and unit.endswith(".service"):
            content += "[Service]\nRestart=no\n"
        atomic_write(self.dropin(unit), content, 0o644)

    def verify_guard(self, unit, off):
        # D-Bus exposes the effective Conditions after all drop-ins and resets.
        encoded = "".join(c if c.isascii() and c.isalnum() else "_%02x" % ord(c) for c in unit)
        data = json.loads(self.run("busctl", "--system", "--json=short", "get-property",
                                  "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/" + encoded,
                                  "org.freedesktop.systemd1.Unit", "Conditions"))
        conditions = data.get("data", [])
        for marker in (STATE_DIR + "/off/" + unit, RUNTIME_DIR + "/stopped/" + unit):
            if not any(len(c) == 5 and c[:4] == ["ConditionPathExists", False, True, marker]
                       for c in conditions):
                raise ValueError("Another systemd override removed lifecycle guard for " + unit)
        if off and unit.endswith(".service") and self.show(unit).get("Restart") != "no":
            raise ValueError("Another systemd override supersedes Restart=no for " + unit)

    def status(self, unit):
        unit = canonical(unit)
        result = self.show(unit)
        intent = self.read()["units"].get(unit, {})
        permanent, stopped = self.markers(unit)
        result.update(unit=unit, off=bool(intent.get("off") or permanent.exists()),
                      stopped=stopped.exists(), autostart=intent.get("autostart"))
        return result

    def conflicts(self):
        """Report pollers; never silently adopt or modify an external watchdog."""
        result = []
        for unit in EXTERNAL_WATCHDOGS:
            state = self.status(unit)
            if state.get("LoadState") not in ("loaded", "masked"):
                continue
            state["conflict"] = state.get("ActiveState") in ("active", "activating", "reloading")
            result.append(state)
        return result

    def change(self, action, unit):
        unit = canonical(unit)
        with self.lock():
            state = self.read()
            live = self.show(unit)
            if live.get("LoadState") not in ("loaded", "masked"):
                raise ValueError("Служба не установлена: " + unit)
            self.check_owned(unit)
            intent = state["units"].setdefault(unit, {"off": False, "autostart": None})
            permanent, stopped = self.markers(unit)
            blocked = intent["off"] or permanent.exists()
            if action in ("start", "restart", "autostart-on") and blocked:
                raise ValueError("Служба постоянно выключена; сначала выполните on: " + unit)
            if action in ("on", "start", "restart", "autostart-on") and (
                    live.get("LoadState") == "masked" or live.get("UnitFileState", "").startswith("masked")):
                raise ValueError("Administrator mask preserved; explicit unmask required for " + unit)
            if action in ("on", "start", "restart", "autostart-on"):
                self.check_snell_selection(unit)
            if action == "off":
                # Record inhibition before any systemd change. On partial failure
                # it stays inhibited and can be retried; never revive it in rollback.
                atomic_write(permanent, "off\n")
                intent.update(off=True, autostart=False)
                self.save(state)
                self.guard(unit, True)
                self.ctl("daemon-reload")
                self.ctl("stop", unit)
                self.ctl("disable", unit)
                if live.get("LoadState") != "masked":
                    self.verify_guard(unit, True)
                if self.show(unit).get("ActiveState") not in ("inactive", "failed"):
                    raise ValueError("Service did not stop: " + unit)
            elif action == "stop":
                atomic_write(stopped, "manual stop\n")
                self.save(state)
                self.guard(unit, blocked)
                self.ctl("daemon-reload")
                self.ctl("stop", unit)
                if live.get("LoadState") != "masked":
                    self.verify_guard(unit, blocked)
            elif action in ("on", "start", "restart"):
                if action == "on":
                    intent.update(off=False, autostart=True)
                # Verify the guard before removing either marker.
                self.guard(unit, False)
                self.ctl("daemon-reload")
                self.verify_guard(unit, False)
                self.save(state)
                permanent.unlink(missing_ok=True)
                stopped.unlink(missing_ok=True)
                if action == "on":
                    self.ctl("enable", unit)
                self.ctl("reset-failed", unit)
                self.ctl("restart" if action == "restart" else "start", unit)
                started = self.show(unit)
                if started.get("ActiveState") != "active" and not (
                        started.get("Type") == "oneshot" and started.get("Result") == "success"):
                    raise ValueError("Service start was skipped or failed: " + unit)
            elif action in ("autostart-on", "autostart-off"):
                intent["autostart"] = action == "autostart-on"
                self.save(state)
                self.ctl("enable" if intent["autostart"] else "disable", unit)
            else:
                raise ValueError("Unknown lifecycle action: " + action)
        return self.status(unit)

    def reconcile(self):
        """Restore guards after installation; never enable or start a unit."""
        with self.lock():
            # Upgrade old installations without changing stop/off intent or file contents.
            for name in (STATE_DIR, STATE_DIR + "/off", RUNTIME_DIR + "/stopped"):
                directory = self.path(name)
                if directory.is_symlink():
                    raise ValueError("Refusing symlink in lifecycle state: " + str(directory))
                if directory.exists():
                    directory.chmod(0o711)
            state = self.read()
            changed = []
            for unit, intent in state["units"].items():
                permanent, stopped = self.markers(unit)
                off = intent["off"] or permanent.exists()
                self.check_owned(unit)
                if off:
                    atomic_write(permanent, "off\n")
                self.guard(unit, off)
                changed.append((unit, off, stopped.exists(), intent.get("autostart")))
            if changed:
                self.ctl("daemon-reload")
            for unit, off, stopped, autostart in changed:
                live = self.show(unit)
                if live.get("LoadState") not in ("loaded", "masked"):
                    continue
                if off or stopped:
                    self.ctl("stop", unit)
                if off or autostart is False:
                    self.ctl("disable", unit)
                if live.get("LoadState") != "masked":
                    self.verify_guard(unit, off)


def unit_menu(controller, units=None):
    while True:
        available = [controller.status(u) for u in (UNITS if units is None else units)]
        available = [s for s in available if s.get("LoadState") in ("loaded", "masked")]
        print("\nУправление службами X-Manager")
        print("Стоп действует до запуска из меню или перезагрузки. Выключение сохраняется после обновления.")
        print("Внешние sing-box/caddy/watchdog изменяются только при явном выборе службы.")
        for i, state in enumerate(available, 1):
            intent = "выключена постоянно" if state["off"] else "ручной стоп" if state["stopped"] else "разрешена"
            print(f"[{i}] {service_name(state['unit'])} — {service_state(state)}")
        choice = input("[0] Назад\nСлужба: ").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(available):
            continue
        unit = available[int(choice) - 1]["unit"]
        action = input("[1] Запустить\n[2] Остановить до запуска/перезагрузки\n[3] Выключить постоянно\n"
                       "[4] Включить и запустить\n[5] Автозапуск вкл.\n[6] Автозапуск выкл.\n"
                       "[7] Перезапустить\n[0] Назад\nДействие: ").strip()
        actions = {"1": "start", "2": "stop", "3": "off", "4": "on", "5": "autostart-on",
                   "6": "autostart-off", "7": "restart"}
        if action == "3" and unit == "fail2ban.service":
            confirmation = input("Выключение Fail2ban отключит защиту от перебора паролей. "
                                 "Выключить постоянно? [y/N]: ").strip().lower()
            if confirmation not in ("y", "yes", "д", "да"):
                continue
        if action in actions:
            try:
                print("Готово: " + service_state(controller.change(actions[action], unit)))
            except (ValueError, OSError, RuntimeError) as error:
                print("Ошибка управления службой:", error)


LABELS = {"tuna-subscriptions.service":"Подписки TUNA", "webdav-tunnel.service":"WebDAV",
          "snell.service":"Snell v5", "mita.service":"Mieru", "wdtt.service":"WDTT",
          "csqtt.service":"CSQTT", "masterdns.service":"MasterDNS", "cottendns.service":"CottenDNS",
          "x-ui.service":"Панель X-UI", "xray.service":"Xray", "fail2ban.service":"Fail2ban",
          "wdtt-tproxy.service":"Маршрутизация WDTT", "volga-cookies.service":"Обновление cookies Волги",
          "volga-cookies.timer":"Расписание обновления cookies", "tuna-healthcheck.service":"Проверка работоспособности",
          "tuna-healthcheck.timer":"Расписание проверок", "vpn-watchdog.service":"Внешний VPN Watchdog",
          "tuna-watchdog.service":"Прежний TUNA Watchdog", "tuna-watchdog.timer":"Расписание прежнего Watchdog"}


def service_name(unit):
    if unit.startswith("openflux@"):
        return "Канал " + unit.split("@")[1].split(".")[0]
    if unit.startswith("snell6@"):
        return "Snell v6 — подключение " + unit.split("@")[1].split(".")[0]
    return LABELS.get(unit, unit.removesuffix(".service").removesuffix(".timer"))


def service_state(state):
    live = {"active":"Работает", "inactive":"Остановлена", "failed":"Ошибка",
            "activating":"Запускается", "deactivating":"Останавливается"}.get(state.get("ActiveState"), "Состояние неизвестно")
    if state.get("off"): live += " · выключена постоянно"
    elif state.get("stopped"): live += " · ручной стоп"
    enabled=state.get("UnitFileState", "")
    boot = "включён" if enabled in ("enabled", "enabled-runtime") else "по запросу" if enabled=="static" else "заблокирован" if enabled.startswith("masked") else "выключен"
    return live + " · автозапуск " + boot


def menu_entries(controller):
    rows=[]; snell=[]; flux=[]; extra=[]
    auxiliary={"wdtt-tproxy.service","volga-cookies.service","volga-cookies.timer","tuna-healthcheck.service",
               "tuna-healthcheck.timer","vpn-watchdog.service","vpn-watchdog.timer","tuna-watchdog.service","tuna-watchdog.timer"}
    for unit in UNITS:
        state=controller.status(unit)
        if state.get("LoadState") not in ("loaded","masked"):continue
        if unit.startswith("snell6@"):
            slot=unit.split("@")[1].split(".")[0]
            if not (controller.path('/etc/snell6/endpoints')/slot/'endpoint.json').is_file() and state.get("ActiveState")!='active':continue
            snell.append(state)
        elif unit=='snell.service':snell.append(state)
        elif unit.startswith('openflux@'):
            slot=unit.split('@')[1].split('.')[0]
            path=controller.path('/etc/openflux/instances')/(slot+'.env')
            configured=path.is_file() and re.search(r'(?m)^URL=["\']?[^"\'\s]',path.read_text())
            if configured or state.get('ActiveState') in ('active','failed'):flux.append(state)
        elif unit in auxiliary:extra.append(state)
        else:rows.append((service_name(unit)+' — '+service_state(state),[unit]))
    if snell:
        active=[service_name(x['unit']) for x in snell if x.get('ActiveState')=='active']
        rows.insert(min(2,len(rows)),('Snell — '+(', '.join(active) if active else 'остановлен'),[x['unit'] for x in snell]))
    if flux:rows.append(('OpenFlux — работают '+str(sum(x.get('ActiveState')=='active' for x in flux))+' из '+str(len(flux))+' каналов',[x['unit'] for x in flux]))
    if extra:rows.append(('Служебные задачи и расписания',[x['unit'] for x in extra]))
    return rows


def menu(controller):
    while True:
        rows=menu_entries(controller)
        print('\nУправление службами')
        print('Выберите службу. Открытие меню ничего не меняет.')
        for i,(label,_) in enumerate(rows,1):print(f'[{i}] {label}')
        pick=input('[0] Назад\nСлужба: ').strip()
        if pick=='0':return
        if pick.isdigit() and 1<=int(pick)<=len(rows):unit_menu(controller,rows[int(pick)-1][1])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["off", "on", "stop", "start", "restart", "autostart-on",
                        "autostart-off", "can-start", "can-enable", "reconcile", "status", "conflicts", "menu"])
    parser.add_argument("unit", nargs="?")
    parser.add_argument("--human",action="store_true")
    args = parser.parse_args(argv)
    controller = Controller()
    if args.action in ("can-start", "can-enable"):
        return 0 if controller.allowed(args.unit, enable=args.action == "can-enable") else 1
    if args.action == "status":
        result = controller.status(args.unit) if args.unit else [controller.status(u) for u in UNITS]
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.action == "conflicts":
        conflicts=controller.conflicts()
        if args.human:
            active=[row for row in conflicts if row.get('conflict')]
            print('Конфликтов watchdog нет.' if not active else 'Обнаружен другой активный watchdog:')
            for row in active:print('  '+service_name(row['unit']))
        else:print(json.dumps(conflicts, ensure_ascii=False, indent=2))
        return 0
    if os.geteuid() != 0:
        raise ValueError("Нужны права root")
    if args.action == "menu":
        menu(controller)
    elif args.action == "reconcile":
        controller.reconcile()
    else:
        print(json.dumps(controller.change(args.action, args.unit), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError) as error:
        print("Ошибка управления службами:", error, file=sys.stderr)
        sys.exit(2)
    except (EOFError, KeyboardInterrupt):
        sys.exit(130)
