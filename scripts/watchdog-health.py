#!/usr/bin/env python3
"""Local health checks with a guarded first-install Xray recovery default.

Restart budgets persist until an explicit reset. External polling watchdogs,
manual lifecycle inhibition, inactive units and installer maintenance inhibit
restarts. TCP/HTTP checks are local observations, not VPN egress tests.
"""
import argparse
from contextlib import contextmanager
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location("health_service_control", Path(__file__).with_name("service-control.py"))
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)
CONFIG = "/etc/x-manager/healthcheck.json"
STATE = "/var/lib/x-manager/healthcheck/state.json"
INSTALL_LOCK = "/run/lock/x-manager-install.lock"
HEALTH_LOCK = "/run/x-manager/healthcheck.lock"
TIMER = "tuna-healthcheck.timer"
EXCLUDED = {"wdtt-tproxy.service", "volga-cookies.service", "tuna-watchdog.service", "vpn-watchdog.service"}
UNITS = tuple(u for u in control.UNITS if u.endswith(".service") and u not in EXCLUDED)


def command(*args):
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("local service command unavailable or timed out") from exc
    if result.returncode:
        # Command output can contain a service's secrets; keep errors bounded.
        raise RuntimeError("local service command failed: " + args[0] + " " + args[1])
    return result.stdout.strip()


def canonical(unit):
    unit = control.canonical(unit)
    if unit not in UNITS:
        raise ValueError("health checks support only selected long-running services")
    return unit


def validate_spec(spec):
    expected = {"kind", "host", "port", "path", "failures", "cooldown", "max_restarts", "timeout"}
    if not isinstance(spec, dict) or set(spec) != expected:
        raise ValueError("invalid health-check fields")
    if spec["kind"] not in ("process", "xray", "tcp", "http"):
        raise ValueError("invalid health-check kind")
    if spec["host"] not in ("127.0.0.1", "::1"):
        raise ValueError("health checks require an explicit numeric loopback address")
    for key, low, high in (("failures", 1, 20), ("cooldown", 30, 86400),
                           ("max_restarts", 0, 20), ("timeout", 1, 5)):
        if type(spec[key]) is not int or not low <= spec[key] <= high:
            raise ValueError("invalid health-check " + key)
    if spec["kind"] not in ("process", "xray") and (type(spec["port"]) is not int or not 1 <= spec["port"] <= 65535):
        raise ValueError("TCP/HTTP health check requires a valid local port")
    if spec["kind"] in ("process", "xray") and spec["port"] is not None:
        raise ValueError("process check does not use a port")
    if not isinstance(spec["path"], str) or not re.fullmatch(r"/[A-Za-z0-9_./~-]{0,255}", spec["path"]):
        raise ValueError("HTTP path must be local, without query, credentials or control characters")
    if spec["path"].startswith("//"):
        raise ValueError("HTTP path must not be an authority URL")
    return spec


def xray_child_probe(pid, timeout, proc_root=Path("/proc")):
    """Inspect only this service's descendants, including children of its threads."""
    deadline = time.monotonic() + timeout
    proc_root = Path(proc_root)
    budget = 512

    def bounded_read(path):
        nonlocal budget
        budget -= 1
        if budget < 0 or time.monotonic() >= deadline:
            raise ValueError("process traversal bound reached")
        with path.open(encoding="ascii") as stream:
            value = stream.read(65537)
        if len(value) > 65536:
            raise ValueError("process data bound reached")
        return value

    def identity(number):
        # comm can contain spaces and parentheses; fields follow its final ')'.
        fields = bounded_read(proc_root / str(number) / "stat").rsplit(")", 1)[1].split()
        return fields[0], int(fields[1]), fields[19]

    try:
        initial = identity(pid)
        if initial[0] in ("Z", "X"):
            return False, "x-ui main process is not running"
        pending, visited = [pid], {pid}
        while pending:
            parent = pending.pop()
            try:
                task_dir = proc_root / str(parent) / "task"
                with os.scandir(task_dir) as tasks:
                    for task in tasks:
                        if time.monotonic() >= deadline:
                            raise ValueError("process traversal timeout")
                        children = bounded_read(Path(task.path) / "children")
                        for token in children.split():
                            child = int(token)
                            if child in visited:
                                continue
                            visited.add(child)
                            if len(visited) > 256:
                                raise ValueError("process count bound reached")
                            try:
                                before = identity(child)
                                if before[0] in ("Z", "X") or before[1] != parent:
                                    continue
                                executable = os.readlink(proc_root / str(child) / "exe")
                                name = Path(executable.removesuffix(" (deleted)")).name
                                if name in ("xray", "xray-linux-amd64"):
                                    after = identity(child)
                                    if (after[0] not in ("Z", "X") and before[1:] == after[1:]
                                            and identity(pid)[1:] == initial[1:]):
                                        return True, "Xray child of x-ui is running; data path was not tested"
                                pending.append(child)
                            except (OSError, IndexError):
                                continue  # A child may exit during this snapshot.
            except FileNotFoundError:
                continue
    except (OSError, ValueError, IndexError):
        return False, "Xray child could not be verified within bounded process inspection"
    return False, "x-ui has no running Xray child"


def local_probe(spec, pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False, "main process is unavailable"
    if spec["kind"] == "process":
        return True, "main process exists; data path was not tested"
    if spec["kind"] == "xray":
        return xray_child_probe(pid, spec["timeout"])
    if spec["kind"] == "tcp":
        try:
            with socket.create_connection((spec["host"], spec["port"]), timeout=spec["timeout"]):
                return True, "loopback listener accepted TCP"
        except OSError:
            return False, "loopback TCP connection failed"
    connection = http.client.HTTPConnection(spec["host"], spec["port"], timeout=spec["timeout"])
    try:
        connection.request("GET", spec["path"], headers={"Connection": "close"})
        response = connection.getresponse()
        status = response.status
        response.close()
        # No proxy environment, DNS, redirects, response body, or remote URLs.
        return 200 <= status < 300, "local HTTP status " + str(status)
    except (OSError, http.client.HTTPException):
        return False, "local HTTP request failed"
    finally:
        connection.close()


class Health:
    def __init__(self, root="/", run=command, probe=local_probe, now=time.time, controller=None):
        self.root = Path(root)
        self.run, self.probe, self.now = run, probe, now
        self.controller = controller or control.Controller(self.root, run)

    def path(self, path):
        result = self.root / path.lstrip("/")
        cursor = result
        while cursor != self.root:
            if cursor.is_symlink():
                raise ValueError("symlink in managed health-check path")
            cursor = cursor.parent
        return result

    def read_json(self, path):
        target = self.path(path)
        if not target.exists():
            return {"schema": 1, "units": {}}
        with target.open(encoding="utf-8") as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError("health-check state exceeds bounded size")
        value = json.loads(data)
        if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("units"), dict):
            raise ValueError("invalid health-check state; refusing to reset it")
        for unit, row in value["units"].items():
            if canonical(unit) != unit:
                raise ValueError("health state must use canonical service names")
            if path == CONFIG:
                validate_spec(row)
                if row["kind"] == "xray" and unit != "x-ui.service":
                    raise ValueError("Xray child check is only supported for x-ui")
            elif (not isinstance(row, dict) or set(row) != {"failures", "attempts", "last_restart", "pid"}
                  or any(type(row.get(key)) is not int or row[key] < 0 for key in row)):
                raise ValueError("invalid restart counters; explicit inspection required")
        return value

    def save(self, path, value):
        control.atomic_write(self.path(path), json.dumps(value, sort_keys=True, indent=2) + "\n")

    @contextmanager
    def lock(self, install_lock_fd=None):
        import fcntl
        streams = []
        try:
            if install_lock_fd is not None:
                # The installer's inherited descriptor shares its flock. Do not
                # unlock/close it, and never skip the installation lock blindly.
                expected = self.path(INSTALL_LOCK).stat()
                inherited = os.fstat(install_lock_fd)
                if (expected.st_dev, expected.st_ino) != (inherited.st_dev, inherited.st_ino):
                    raise ValueError("installer lock descriptor does not refer to installation lock")
                fcntl.flock(install_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            names = (HEALTH_LOCK,) if install_lock_fd is not None else (INSTALL_LOCK, HEALTH_LOCK)
            for name in names:
                path = self.path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                stream = os.fdopen(fd, "a")
                streams.append(stream)
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    yield False
                    return
            yield True
        finally:
            for stream in reversed(streams):
                stream.close()

    def show(self, unit):
        raw = self.run("systemctl", "show", unit, "--property=LoadState,ActiveState,MainPID,Type,UnitFileState")
        return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)

    def conflicts(self):
        return [s["unit"] for s in self.controller.conflicts() if s["conflict"]]

    def report(self):
        return {"config": self.read_json(CONFIG), "counters": self.read_json(STATE),
                "conflicting_watchdogs": self.conflicts(),
                "timer": self.show("tuna-healthcheck.timer"),
                "note": "local checks only; set never enables timer; bootstrap preserves existing configuration"}

    def bootstrap(self, install_lock_fd=None, new_timer=False, enable_timer=False):
        if new_timer and install_lock_fd is None:
            raise ValueError("new timer bootstrap requires the inherited installer lock")
        result = {"action": "bootstrap", "unit": "x-ui.service", "status": "preserved",
                  "timer_enabled_by_this_command": False}
        with self.lock(install_lock_fd) as acquired:
            if not acquired:
                raise ValueError("installation or another health operation is in progress")
            # Presence itself records ownership/opt-out, including an empty file.
            target = self.path(CONFIG)
            if target.exists():
                return dict(result, reason="existing health configuration preserved")
            with self.controller.lock():
                live = self.show("x-ui.service")
                if (live.get("LoadState") != "loaded" or live.get("ActiveState") != "active"
                        or live.get("Type") == "oneshot" or int(live.get("MainPID", "0")) <= 0
                        or live.get("UnitFileState", "").startswith("masked")
                        or not self.controller.allowed("x-ui.service")):
                    return dict(result, reason="x-ui is inactive, unavailable or inhibited")
                if self.conflicts():
                    return dict(result, reason="another polling watchdog owns recovery")
                timer = self.show(TIMER)
                service = self.show("tuna-healthcheck.service")
                if (timer.get("LoadState") != "loaded" or service.get("LoadState") != "loaded"
                        or timer.get("UnitFileState", "").startswith("masked")
                        or service.get("UnitFileState", "").startswith("masked")
                        or not self.controller.allowed(TIMER)
                        or not self.controller.allowed(TIMER, enable=True)
                        or not self.controller.allowed("tuna-healthcheck.service")):
                    return dict(result, reason="health timer or service unavailable or explicitly inhibited")
                # Existing inactive/disabled timer may express direct systemctl
                # intent. Only a genuinely newly installed timer can be enabled.
                if not (new_timer or enable_timer) and (timer.get("ActiveState") != "active"
                                      or timer.get("UnitFileState") not in ("enabled", "enabled-runtime")):
                    return dict(result, reason="existing timer stop or disable preserved")
                if timer.get("ActiveState") not in ("active", "inactive", "failed"):
                    raise ValueError("health timer is transitioning; retry bootstrap later")
                if timer.get("UnitFileState") not in ("enabled", "enabled-runtime", "disabled"):
                    raise ValueError("unsupported health timer enable state")
                # Validate counters before setup without erasing a previous budget.
                self.read_json(STATE)
                default = {"kind": "xray", "host": "127.0.0.1", "port": None, "path": "/",
                           "failures": 2, "cooldown": 60, "max_restarts": 5, "timeout": 3}
                healthy, reason = self.probe(default, int(live["MainPID"]))
                if not healthy:
                    return dict(result, reason="Xray process layout was not verified: " + reason)
                current_service, current_timer = self.show("x-ui.service"), self.show(TIMER)
                if (current_service.get("ActiveState") != "active"
                        or current_service.get("MainPID") != live["MainPID"]
                        or current_service.get("UnitFileState", "").startswith("masked")
                        or current_timer != timer or self.conflicts()):
                    return dict(result, reason="service, timer or watchdog state changed during setup probe")
                changed_enabled = changed_active = False
                try:
                    self.save(CONFIG, {"schema": 1, "units": {"x-ui.service": default}})
                    if timer.get("UnitFileState") == "disabled":
                        changed_enabled = True
                        self.run("systemctl", "enable", TIMER)
                    if timer.get("ActiveState") != "active":
                        changed_active = True
                        self.run("systemctl", "start", TIMER)
                    current = self.show(TIMER)
                    if (current.get("ActiveState") != "active"
                            or current.get("UnitFileState") not in ("enabled", "enabled-runtime")):
                        raise RuntimeError("health timer activation verification failed")
                except (OSError, ValueError, RuntimeError) as failure:
                    rollback_errors = []
                    for changed, action in ((changed_active, "stop"), (changed_enabled, "disable")):
                        if changed:
                            try:
                                self.run("systemctl", action, TIMER)
                            except (OSError, RuntimeError) as error:
                                rollback_errors.append(str(error))
                    try:
                        target.unlink(missing_ok=True)
                    except OSError as error:
                        rollback_errors.append(str(error))
                    try:
                        restored = self.show(TIMER)
                        if (restored.get("UnitFileState") != timer.get("UnitFileState")
                                or (restored.get("ActiveState") == "active") != (timer.get("ActiveState") == "active")):
                            rollback_errors.append("timer state restoration could not be verified")
                    except (OSError, RuntimeError) as error:
                        rollback_errors.append(str(error))
                    if rollback_errors:
                        raise RuntimeError("health bootstrap failed; rollback incomplete: "
                                           + "; ".join(rollback_errors)) from failure
                    raise
                return dict(result, status="configured", timer_enabled_by_this_command=changed_enabled,
                            reason="bounded Xray child recovery configured")

    def configure(self, action, unit, spec=None):
        unit = canonical(unit)
        if action == "set":
            validate_spec(spec)
            if spec["kind"] == "xray" and unit != "x-ui.service":
                raise ValueError("Xray child check is only supported for x-ui")
        with self.lock() as acquired:
            if not acquired:
                raise ValueError("installation or another health operation is in progress")
            config, state = self.read_json(CONFIG), self.read_json(STATE)
            if action == "set":
                live = self.show(unit)
                if live.get("LoadState") not in ("loaded", "masked") or live.get("Type") == "oneshot":
                    raise ValueError("health checks require an installed long-running unit")
                if spec["max_restarts"] and self.conflicts():
                    raise ValueError("another polling watchdog is active; resolve ownership explicitly first")
                config["units"][unit] = spec
                # Editing a check never replenishes spent restart attempts.
                self.save(CONFIG, config)
            elif action == "remove":
                config["units"].pop(unit, None)
                self.save(CONFIG, config)
            elif action == "reset":
                state["units"].pop(unit, None)
                self.save(STATE, state)
            else:
                raise ValueError("unknown health configuration action")
        return {"action": action, "unit": unit, "timer_enabled_by_this_command": False}

    def check(self):
        with self.lock() as acquired:
            if not acquired:
                return {"status": "skipped", "reason": "maintenance or concurrent health operation", "units": []}
            config, state = self.read_json(CONFIG), self.read_json(STATE)
            if not config["units"]:
                return {"status": "unconfigured", "units": []}
            conflicts = self.conflicts()
            if conflicts:
                return {"status": "blocked", "reason": "another polling watchdog is active", "conflicts": conflicts, "units": []}
            outcomes = []
            for unit, spec in config["units"].items():
                # Keep explicit menu stop/off serialized against our final check
                # and restart. Never wait for the installer: its lock was tried
                # nonblocking before this one.
                with self.controller.lock():
                    live = self.show(unit)
                    counter = state["units"].setdefault(unit, {"failures": 0, "attempts": 0, "last_restart": 0, "pid": 0})
                    if (not self.controller.allowed(unit) or live.get("ActiveState") != "active"
                            or live.get("Type") == "oneshot" or live.get("UnitFileState", "").startswith("masked")):
                        counter["failures"] = 0
                        outcomes.append({"unit": unit, "status": "skipped", "reason": "inactive, oneshot, masked or explicitly inhibited"})
                        continue
                    pid = int(live.get("MainPID", "0"))
                    if counter["pid"] != pid:
                        counter.update(pid=pid, failures=0)
                    healthy, reason = self.probe(spec, pid) if pid > 0 else (False, "active unit has no main PID")
                    counter["failures"] = 0 if healthy else min(20, counter["failures"] + 1)
                    outcome = {"unit": unit, "status": "healthy" if healthy else "unhealthy", "reason": reason,
                               "failures": counter["failures"], "attempts": counter["attempts"]}
                    outcomes.append(outcome)
                    if healthy or counter["failures"] < spec["failures"]:
                        continue
                    if spec["max_restarts"] == 0:
                        outcome.update(status="monitor-only", reason="automatic health restarts are disabled")
                        continue
                    if counter["attempts"] >= spec["max_restarts"]:
                        outcome.update(status="exhausted", reason="restart allowance spent; explicit reset required")
                        continue
                    now = int(self.now())
                    if counter["attempts"] and now - counter["last_restart"] < spec["cooldown"]:
                        outcome["status"] = "cooldown"
                        continue
                    current = self.show(unit)
                    if (current.get("ActiveState") != "active" or current.get("MainPID") != live.get("MainPID")
                            or current.get("UnitFileState", "").startswith("masked") or not self.controller.allowed(unit)):
                        outcome.update(status="skipped", reason="service state changed during probe")
                        continue
                    if self.conflicts():
                        outcome.update(status="blocked", reason="polling watchdog became active during probe")
                        continue
                    if unit.startswith("openflux@"):
                        loader = importlib.util.spec_from_file_location("health_openflux_budget", Path(__file__).with_name("openflux-watchdog.py"))
                        shared_module = importlib.util.module_from_spec(loader)
                        loader.loader.exec_module(shared_module)
                        shared = shared_module.Watchdog(root=self.root, run=self.run, controller=self.controller)
                        if not shared.status()["configured"] or not shared.reserve(unit):
                            outcome.update(status="exhausted", reason="OpenFlux shared restart budget unavailable or exhausted")
                            continue
                    counter.update(attempts=counter["attempts"] + 1, last_restart=now, failures=0)
                    # Persist before requesting the restart; a failed command or
                    # crash cannot erase an attempt and cause an infinite loop.
                    self.save(STATE, state)
                    try:
                        self.run("systemctl", "restart", unit)
                        if self.show(unit).get("ActiveState") != "active":
                            raise RuntimeError("service is not active after restart")
                        outcome.update(status="restarted", attempts=counter["attempts"])
                    except (RuntimeError, OSError) as error:
                        outcome.update(status="restart-failed", attempts=counter["attempts"], reason=str(error))
            self.save(STATE, state)
            return {"status": "checked", "units": outcomes}


def human_result(result):
    if "config" in result:
        units = result["config"]["units"]
        timer = result["timer"].get("ActiveState") == "active"
        print("Автоматические проверки: " + ("включены" if timer else "выключены"))
        if not units:
            print("Проверки не настроены. Выберите [2] «Добавить или изменить проверку».")
            print("Ни одна служба этим механизмом сейчас не проверяется.")
        kinds = {"process": "наличие процесса", "xray": "процесс Xray внутри x-ui",
                 "tcp": "ответ TCP", "http": "ответ HTTP"}
        for unit, spec in units.items():
            used = result["counters"]["units"].get(unit, {}).get("attempts", 0)
            limit = spec["max_restarts"]
            remaining = max(0, limit - used)
            policy = f"перезапусков осталось {remaining} из {limit}" if limit else "только наблюдение"
            print(f"\nСлужба: {unit}")
            print("  Проверка: " + kinds[spec['kind']])
            print(f"  Ошибок подряд до действия: {spec['failures']}")
            print(f"  Пауза между перезапусками: {spec['cooldown']} с")
            print(f"  Лимит перезапусков: {limit}")
            print(f"  Использовано попыток: {used}")
            print(f"  Осталось попыток: {remaining}")
            if not limit: print("  Режим: только наблюдение")
        if result["conflicting_watchdogs"]:
            print("Конфликт с другим watchdog: " + ", ".join(result["conflicting_watchdogs"]))
    elif "action" in result:
        if result["action"] == "bootstrap":
            if result["status"] == "configured":
                print("Базовое восстановление Xray настроено: после 2 ошибок, максимум 5 перезапусков x-ui, пауза 60 с.")
                print("Таймер проверок включён. Настройка сама не перезапускает x-ui.")
            else:
                reasons = {
                    "existing health configuration preserved": "Настройки проверок уже сохранены. Повторное применение их не меняет.",
                    "x-ui is inactive, unavailable or inhibited": "Панель X-UI не запущена или выключена; проверка не включалась.",
                    "another polling watchdog owns recovery": "Восстановлением управляет другой watchdog.",
                    "existing timer stop or disable preserved": "Сохранено прежнее отключение таймера.",
                    "health timer or service unavailable or explicitly inhibited": "Таймер проверок отсутствует или явно выключен."}
                print(reasons.get(result["reason"], "Базовая проверка не включена: " + result["reason"]))
            return
        label = {"set": "Проверка сохранена", "remove": "Проверка удалена", "reset": "Счётчик попыток сброшен"}
        print(label[result["action"]] + ": " + result["unit"])
    else:
        labels = {"unconfigured": "Проверки не настроены. Добавьте проверку через пункт [2].",
                  "skipped": "Проверка пропущена: обслуживание или другая операция выполняется сейчас.",
                  "blocked": "Проверка заблокирована конфликтом watchdog.", "checked": "Проверки завершены."}
        print(labels.get(result["status"], result["status"]))
        states = {"healthy": "проверка пройдена", "unhealthy": "проверка не пройдена",
                  "skipped": "пропущено: служба остановлена, запрещена или её состояние изменилось",
                  "monitor-only": "ошибка; включено только наблюдение",
                  "exhausted": "лимит перезапусков исчерпан", "cooldown": "ожидание между попытками",
                  "restarted": "служба перезапущена", "restart-failed": "перезапуск не удался",
                  "blocked": "конфликт watchdog"}
        for row in result.get("units", []):
            print("  " + row["unit"] + ": " + states.get(row["status"], row["status"]))
            if row.get("reason") and row["status"] in ("unhealthy", "restart-failed"):
                print("    Причина: " + row["reason"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("report", "set", "remove", "check", "reset", "bootstrap"))
    parser.add_argument("unit", nargs="?")
    parser.add_argument("--kind", choices=("process", "xray", "tcp", "http"), default="process")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int)
    parser.add_argument("--path", default="/")
    parser.add_argument("--failures", type=int, default=3)
    parser.add_argument("--cooldown", type=int, default=300)
    parser.add_argument("--max-restarts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--human", action="store_true", help="Readable menu output")
    parser.add_argument("--require-configured", action="store_true", help="Report exits 3 if no checks exist")
    parser.add_argument("--install-lock-fd", type=int, help="Inherited installer lock descriptor (bootstrap only)")
    parser.add_argument("--new-timer", action="store_true", help="Installer created a previously absent timer")
    parser.add_argument("--enable-timer", action="store_true", help="Explicitly enable baseline timer, preserving lifecycle inhibits")
    args = parser.parse_args(argv)
    if args.require_configured and args.action != "report":
        parser.error("--require-configured is only valid for report")
    if (args.install_lock_fd is not None or args.new_timer or args.enable_timer) and args.action != "bootstrap":
        parser.error("installer and timer activation options are only valid for bootstrap")
    if args.action != "report" and os.geteuid() != 0:
        parser.error("mutating health operations require root")
    health = Health()
    if args.action == "bootstrap":
        result = health.bootstrap(args.install_lock_fd, args.new_timer, args.enable_timer)
    elif args.action in ("report", "check"):
        result = getattr(health, args.action)()
    else:
        spec = {key: getattr(args, key) for key in ("kind", "host", "port", "path", "failures", "cooldown", "max_restarts", "timeout")}
        result = health.configure(args.action, args.unit, spec)
    if args.human:
        human_result(result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.require_configured and not result["config"]["units"]:
        return 3
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print("Health check error: " + str(error), file=sys.stderr)
        raise SystemExit(1)
