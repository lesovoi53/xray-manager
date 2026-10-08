#!/usr/bin/env python3
"""Explicit BBR/fq default profile with preview, effective verification and rollback.

Adaptive mode also sizes buffers and conntrack from effective RAM. Module loading
requires the explicit prepare command. No interface restart, reboot or route edits.
"""
import argparse
from contextlib import contextmanager
import fnmatch
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

CONFIG = "/etc/sysctl.d/90-tuna-network.conf"
STATE = "/var/lib/x-manager/network-profile/snapshot.json"
HEADER = "# Managed by X-Manager network-profile.py\n"
VALUES = {"net.ipv4.tcp_congestion_control": "bbr", "net.core.default_qdisc": "fq"}
CONTENT = HEADER + "".join(key + " = " + value + "\n" for key, value in VALUES.items())
NOTE = "Defaults affect new TCP sockets/new qdiscs; existing interface queues are unchanged. No UDP speed claim."
MODULES = "/etc/modules-load.d/90-tuna-network.conf"
MODULE_CONTENT = HEADER + "tcp_bbr\nnf_conntrack\n"
CT = "net.netfilter.nf_conntrack_"
TIMEOUTS = {CT + "tcp_timeout_" + key: value for key, value in
            (("established", "7200"), ("time_wait", "30"), ("close_wait", "15"), ("fin_wait", "30"))}
ADAPTIVE = dict(VALUES, **{
    "net.core.rmem_max": "", "net.core.wmem_max": "",
    "net.ipv4.tcp_rmem": "", "net.ipv4.tcp_wmem": "", CT + "max": "",
    "net.core.netdev_max_backlog": "", "net.core.somaxconn": "",
    "net.ipv4.tcp_max_syn_backlog": "",
    "net.ipv4.tcp_keepalive_time": "300", "net.ipv4.tcp_keepalive_intvl": "15",
    "net.ipv4.tcp_keepalive_probes": "5", "net.ipv4.tcp_fin_timeout": "15", **TIMEOUTS})
MANAGED_KEYS = tuple(ADAPTIVE)


def valid_value(key, value):
    if not isinstance(value, str):
        return False
    if key in VALUES:
        return bool(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value))
    if key not in ADAPTIVE:
        return False
    parts = value.split()
    expected = 3 if key in ("net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem") else 1
    return (len(parts) == expected and all(re.fullmatch(r"[0-9]{1,19}", p) and
            0 <= int(p) < 2**63 for p in parts) and
            (expected == 1 or 0 < int(parts[0]) <= int(parts[1]) <= int(parts[2])))


def content(values):
    return HEADER + "".join(key + " = " + value + "\n" for key, value in values.items())


def atomic_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Refusing symlink: " + str(path))
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Required local command unavailable or timed out: " + args[0]) from exc
    if result.returncode:
        raise RuntimeError("Local command failed: " + args[0])
    return result.stdout.strip()


class Profile:
    def __init__(self, root="/", run=None):
        self.root = Path(root)
        self.run = run or command

    def path(self, name):
        return self.root / name.lstrip("/")

    def read(self, name):
        with self.path(name).open("r", encoding="utf-8") as stream:
            content = stream.read(262145)
        if len(content) > 262144:
            raise ValueError("File exceeds bounded read: " + name)
        return content

    def effective(self, keys=VALUES):
        values = {}
        for key in keys:
            value = self.read("/proc/sys/" + key.replace(".", "/")).strip()
            if not valid_value(key, value):
                raise ValueError("Unexpected effective sysctl value: " + key)
            values[key] = " ".join(value.split())
        return values

    def source_declarations(self, keys=VALUES):
        records = []
        # List every declaration, including shadowed vendor basenames. Conservative
        # blocking is intentional; loader choice and runtime provenance are unknown.
        paths = [self.path("/etc/sysctl.conf")]
        for directory in ("/usr/lib/sysctl.d", "/usr/local/lib/sysctl.d",
                          "/lib/sysctl.d", "/run/sysctl.d", "/etc/sysctl.d"):
            paths.extend(sorted(self.path(directory).glob("*.conf")))
        if len(paths) > 256:
            raise ValueError("Too many sysctl files for bounded conflict scan")
        for path in paths:
            if path == self.path(CONFIG) or not path.exists():
                continue
            name = "/" + path.relative_to(self.root).as_posix()
            for line_no, line in enumerate(self.read(name).splitlines(), 1):
                match = re.match(r"\s*-?([^\s=]+)\s*=\s*([^#;]+)", line)
                if not match:
                    continue
                key = match[1].replace("/", ".")
                for target in keys:
                    if fnmatch.fnmatchcase(target, key):
                        value = match[2].strip()
                        # Selected keys are scalar kernel identifiers, never config blobs.
                        if not valid_value(target, value):
                            value = "<non-scalar declaration>"
                        else:
                            value = " ".join(value.split())
                        records.append({"key": target, "value": value, "file": name, "line": line_no,
                                        "potential_later_override": path.name >= Path(CONFIG).name or
                                        name == "/etc/sysctl.conf"})
        return records

    def plan(self, adaptive=False):
        if adaptive:
            return self.adaptive_plan()
        current = self.effective()
        available = self.read("/proc/sys/net/ipv4/tcp_available_congestion_control").split()
        declarations = self.source_declarations()
        blockers = []
        if "bbr" not in available:
            blockers.append("BBR is not available in the running kernel; no modules will be loaded automatically.")
        for declaration in declarations:
            if declaration["potential_later_override"] and declaration["value"] != VALUES[declaration["key"]]:
                blockers.append("Potential later override: %s:%d (%s)" % (
                    declaration["file"], declaration["line"], declaration["key"]))
        config = self.path(CONFIG)
        if config.is_symlink() or (config.exists() and not self.read(CONFIG).startswith(HEADER)):
            blockers.append("Managed target already belongs to another configuration; refusing replacement.")
        if self.path(STATE).exists() or self.path(STATE).is_symlink():
            blockers.append("An existing transaction snapshot requires rollback or inspection first.")
        return {"action": "plan", "ready": not blockers, "current": current,
                "desired": VALUES.copy(), "file": CONFIG, "file_preview": CONTENT,
                "declarations": declarations, "blockers": blockers, "note": NOTE,
                "fq_support": "Kernel validates the requested default on apply; active qdiscs are not changed."}

    @contextmanager
    def lock(self):
        import fcntl
        directory = self.path(STATE).parent
        directory.mkdir(parents=True, exist_ok=True)
        lockpath = directory / "lock"
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield

    def save_snapshot(self, snapshot):
        atomic_write(self.path(STATE), json.dumps(snapshot, indent=2) + "\n")

    def set_values(self, values):
        for key in values:
            self.run("sysctl", "-w", key + "=" + values[key])
        if self.effective(values) != values:
            raise RuntimeError("Effective sysctl verification failed")

    def restore(self, snapshot):
        # Try every key even if one write fails, then restore persistence. Keep a
        # retryable snapshot if any step failed (including the effective read).
        errors = []
        for key in snapshot["before"]:
            try:
                self.run("sysctl", "-w", key + "=" + snapshot["before"][key])
            except (OSError, ValueError, RuntimeError) as error:
                errors.append(error)
        previous = snapshot["file_before"]
        try:
            if previous is None:
                self.path(CONFIG).unlink(missing_ok=True)
            else:
                atomic_write(self.path(CONFIG), previous["content"], previous["mode"])
            if "modules_before" in snapshot:
                self.restore_file(MODULES, snapshot["modules_before"])
            if self.effective(snapshot["before"]) != snapshot["before"]:
                errors.append(RuntimeError("Effective rollback verification failed"))
        except (OSError, ValueError, RuntimeError) as error:
            errors.append(error)
        if errors:
            snapshot["phase"] = "rollback_failed"
            self.save_snapshot(snapshot)
            raise RuntimeError("Rollback incomplete; snapshot retained at " + STATE) from errors[0]
        self.path(STATE).unlink()

    def apply(self, adaptive=False):
        if adaptive:
            return self.adaptive_apply()
        with self.lock():
            plan = self.plan()
            if not plan["ready"]:
                raise ValueError("; ".join(plan["blockers"]))
            config = self.path(CONFIG)
            previous = ({"content": self.read(CONFIG), "mode": stat.S_IMODE(config.stat().st_mode)}
                        if config.exists() else None)
            snapshot = {"schema_version": 1, "phase": "applying", "before": plan["current"],
                        "desired": VALUES.copy(), "file_before": previous, "managed_content": CONTENT}
            self.save_snapshot(snapshot)
            try:
                atomic_write(config, CONTENT, 0o644)
                self.set_values(VALUES)
                snapshot["phase"] = "applied"
                self.save_snapshot(snapshot)
            except Exception as error:
                try:
                    self.restore(snapshot)
                except Exception as rollback_error:
                    raise RuntimeError("Apply failed and rollback incomplete; snapshot retained at " + STATE) from rollback_error
                raise RuntimeError("Apply failed; original runtime and file restored") from error
            return {"action": "apply", "status": "applied", "effective": self.effective(),
                    "snapshot": STATE, "note": NOTE}

    def rollback(self):
        with self.lock():
            snapshot = self.load_snapshot()
            desired = snapshot["desired"]
            current = self.effective(snapshot["before"])
            if any(current[key] not in (desired[key], snapshot["before"][key]) for key in snapshot["before"]):
                raise ValueError("Runtime changed after transaction; refusing to overwrite administrator changes")
            config = self.path(CONFIG)
            file_now = self.read(CONFIG) if config.exists() else None
            prior = snapshot.get("file_before")
            file_before = prior["content"] if prior is not None else None
            recoverable = snapshot.get("phase") in ("applying", "rollback_failed") and file_now == file_before
            if snapshot["phase"] == "prepared":
                recoverable = file_now == file_before
            if config.is_symlink() or (file_now != snapshot["managed_content"] and not recoverable):
                raise ValueError("Managed file changed after transaction; refusing to overwrite administrator changes")
            if "modules_before" in snapshot:
                prior_module = snapshot["modules_before"]
                prior_text = prior_module["content"] if prior_module else None
                module_now = self.read(MODULES) if self.path(MODULES).exists() else None
                if self.path(MODULES).is_symlink() or module_now not in (MODULE_CONTENT, prior_text):
                    raise ValueError("Managed file changed after transaction; refusing to overwrite administrator changes")
            self.restore(snapshot)
            return {"action": "rollback", "status": "restored", "effective": self.effective(snapshot["before"]), "note": NOTE}

    def file_snapshot(self, name):
        path = self.path(name)
        if path.is_symlink():
            raise ValueError("Refusing symlink: " + name)
        return {"content": self.read(name), "mode": stat.S_IMODE(path.stat().st_mode)} if path.exists() else None

    def restore_file(self, name, previous):
        if previous is None:
            self.path(name).unlink(missing_ok=True)
        else:
            atomic_write(self.path(name), previous["content"], previous["mode"])

    def load_snapshot(self):
        if self.path(STATE).is_symlink():
            raise ValueError("Invalid transaction snapshot")
        snapshot = json.loads(self.read(STATE))
        desired, before = snapshot.get("desired", {}), snapshot.get("before", {})
        version = snapshot.get("schema_version")
        valid = (version in (1, 2) and isinstance(desired, dict) and isinstance(before, dict)
                 and set(before) == set(desired) and all(valid_value(k, v) for k, v in before.items())
                 and all(valid_value(k, v) for k, v in desired.items())
                 and snapshot.get("phase") in ("prepared", "applying", "applied", "rollback_failed"))
        if version == 1:
            valid = valid and desired == VALUES and snapshot.get("managed_content") == CONTENT
        else:
            valid = (valid and snapshot.get("adaptive") is True and "modules_before" in snapshot
                     and snapshot.get("managed_content") == (content(desired) if desired else "")
                     and (set(VALUES).issubset(desired) or not desired))
        for field in ("file_before", "modules_before"):
            prior = snapshot.get(field)
            valid = valid and (prior is None or (isinstance(prior, dict) and
                isinstance(prior.get("content"), str) and type(prior.get("mode")) is int and 0 <= prior["mode"] <= 0o777))
        if not valid:
            raise ValueError("Invalid transaction snapshot")
        return snapshot

    def memory(self):
        match = re.search(r"(?m)^MemTotal:\s+(\d+)\s+kB\s*$", self.read("/proc/meminfo"))
        if not match or int(match[1]) == 0:
            raise ValueError("Cannot determine physical RAM")
        total = int(match[1]) * 1024
        limits = []
        # Check the process cgroup and each ancestor: parents also constrain RAM.
        entries = self.read("/proc/self/cgroup").splitlines() if self.path("/proc/self/cgroup").exists() else []
        for entry in entries:
            _, controllers, relative = entry.split(":", 2)
            if controllers and "memory" not in controllers.split(","):
                continue
            if ".." in Path(relative).parts:
                raise ValueError("Invalid cgroup memory path")
            base = self.path("/sys/fs/cgroup" + ("/memory" if controllers else ""))
            suffix = "memory.limit_in_bytes" if controllers else "memory.max"
            directory = base / relative.lstrip("/")
            while True:
                path = directory / suffix
                if path.exists():
                    value = path.read_text().strip()
                    if value != "max":
                        if not re.fullmatch(r"[0-9]{1,20}", value) or int(value) <= 0:
                            raise ValueError("Invalid cgroup memory limit")
                        limits.append(int(value))
                if directory == base:
                    break
                directory = directory.parent
        # Namespaced cgroup mounts commonly expose only the hierarchy root.
        for name in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
            if self.path(name).exists():
                value = self.read(name).strip()
                if value != "max":
                    if not re.fullmatch(r"[0-9]{1,20}", value) or int(value) <= 0:
                        raise ValueError("Invalid cgroup memory limit")
                    limits.append(int(value))
        effective = min([total] + limits)
        tier = next((i for i, limit in enumerate((1, 2, 4)) if effective < limit * 1024**3), 3)
        return {"physical_bytes": total, "cgroup_limit_bytes": min(limits) if limits else None,
                "effective_bytes": effective, "tier": ("<1 GiB", "1–<2 GiB", "2–<4 GiB", ">=4 GiB")[tier],
                "buffer_bytes": (4, 8, 16, 16)[tier] * 1024**2,
                "conntrack_max": (65536, 131072, 262144, 524288)[tier],
                "backlog": (4096, 8192, 16384, 16384)[tier]}

    def adaptive_plan(self):
        memory = self.memory()
        current, warnings, blockers, dependencies = {}, [], [], []
        for key in ADAPTIVE:
            if self.path("/proc/sys/" + key.replace(".", "/")).exists():
                current.update(self.effective([key]))
            elif key in TIMEOUTS:
                warnings.append("Параметр отсутствует, пропущен: " + key)
            elif key == CT + "max":
                dependencies.append("nf_conntrack")
            else:
                blockers.append("Unsupported kernel parameter: " + key)
        if "bbr" not in self.read("/proc/sys/net/ipv4/tcp_available_congestion_control").split():
            dependencies.append("tcp_bbr")
        desired = {k: v for k, v in ADAPTIVE.items() if k in current}
        for key in desired:
            if key in ("net.core.rmem_max", "net.core.wmem_max"):
                target = memory["buffer_bytes"]
            elif key == CT + "max":
                target = memory["conntrack_max"]
            elif key in ("net.core.netdev_max_backlog", "net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog"):
                target = memory["backlog"]
            elif key in ("net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"):
                triple = [int(v) for v in current[key].split()]
                target = memory["buffer_bytes"]
                if triple[2] > target:
                    warnings.append("Сохранён больший текущий лимит: " + key)
                triple[2] = max(target, triple[2])
                desired[key] = " ".join(map(str, triple))
                continue
            else:
                continue
            existing = int(current[key])
            desired[key] = str(max(existing, target))
            if existing > target:
                warnings.append("Сохранён больший текущий лимит: " + key)
        declarations = self.source_declarations(ADAPTIVE)
        for declaration in declarations:
            if declaration["key"] not in desired:
                continue
            admin = declaration["file"].startswith(("/etc/", "/run/"))
            if (declaration["potential_later_override"] or admin) and declaration["value"] != desired[declaration["key"]]:
                blockers.append("Potential later override: %s:%d (%s)" % (
                    declaration["file"], declaration["line"], declaration["key"]))
        for name in (CONFIG, MODULES):
            path = self.path(name)
            if path.is_symlink() or (path.exists() and not self.read(name).startswith(HEADER)):
                blockers.append("Managed target already belongs to another configuration; refusing replacement.")
        already = False
        if self.path(STATE).exists() or self.path(STATE).is_symlink():
            try:
                snapshot = self.load_snapshot()
                if snapshot.get("adaptive") is not True:
                    raise ValueError("An existing transaction snapshot requires rollback or inspection first.")
                if snapshot["phase"] == "applied":
                    already = (snapshot["desired"] == desired and current == desired and
                               self.read(CONFIG) == snapshot["managed_content"] and self.read(MODULES) == MODULE_CONTENT)
                    if not already:
                        raise ValueError("Runtime changed after transaction; refusing to overwrite administrator changes")
                elif snapshot["phase"] != "prepared":
                    raise ValueError("An existing transaction snapshot requires rollback or inspection first.")
                else:
                    if self.file_snapshot(CONFIG) != snapshot["file_before"] or self.read(MODULES) != MODULE_CONTENT:
                        raise ValueError("Managed file changed after transaction; refusing to overwrite administrator changes")
            except (OSError, ValueError) as error:
                blockers.append(str(error))
        prepared = self.path(MODULES).exists() and self.read(MODULES) == MODULE_CONTENT
        if not prepared or not self.path(STATE).exists():
            dependencies.append("modules-load persistence")
        return {"action": "plan", "adaptive": True, "ready": not blockers and not dependencies,
                "preflight_ready": not blockers, "needs_prepare": dependencies,
                "already_applied": already, "current": current, "desired": desired,
                "memory": memory, "warnings": warnings, "file": CONFIG, "file_preview": content(desired),
                "declarations": declarations, "blockers": blockers, "note": NOTE}

    def prepare(self, adaptive=False):
        if not adaptive:
            raise ValueError("prepare requires --adaptive")
        with self.lock():
            plan = self.adaptive_plan()
            if not plan["preflight_ready"]:
                raise ValueError("; ".join(plan["blockers"]))
            if plan["already_applied"]:
                return dict(plan, action="prepare", status="unchanged")
            if self.path(STATE).exists():
                snapshot = self.load_snapshot()
            else:
                snapshot = {"schema_version": 2, "adaptive": True, "phase": "prepared", "before": {},
                            "desired": {}, "managed_content": "", "file_before": self.file_snapshot(CONFIG),
                            "modules_before": self.file_snapshot(MODULES)}
                self.save_snapshot(snapshot)
            try:
                for module in ("tcp_bbr", "nf_conntrack"):
                    if module in plan["needs_prepare"]:
                        self.run("modprobe", module)
                atomic_write(self.path(MODULES), MODULE_CONTENT, 0o644)
                after = self.adaptive_plan()
                if not after["ready"]:
                    raise RuntimeError("Dependency preparation failed: " + "; ".join(after["blockers"] + after["needs_prepare"]))
            except Exception:
                self.restore(snapshot)
                raise
            return dict(after, action="prepare", status="prepared", snapshot=STATE)

    def adaptive_apply(self):
        with self.lock():
            plan = self.adaptive_plan()
            if not plan["ready"]:
                raise ValueError("; ".join(plan["blockers"] + ["Run prepare --adaptive: " + x for x in plan["needs_prepare"]]))
            if plan["already_applied"]:
                return dict(plan, action="apply", status="unchanged", effective=plan["current"], snapshot=STATE)
            if not self.path(STATE).exists():
                raise ValueError("Run prepare --adaptive before apply")
            snapshot = self.load_snapshot()
            snapshot.update(phase="applying", before=plan["current"], desired=plan["desired"], managed_content=plan["file_preview"])
            self.save_snapshot(snapshot)
            try:
                atomic_write(self.path(CONFIG), snapshot["managed_content"], 0o644)
                self.set_values(snapshot["desired"])
                snapshot["phase"] = "applied"
                self.save_snapshot(snapshot)
            except Exception as error:
                try:
                    self.restore(snapshot)
                except Exception as rollback_error:
                    raise RuntimeError("Apply failed and rollback incomplete; snapshot retained at " + STATE) from rollback_error
                raise RuntimeError("Apply failed; original runtime and file restored") from error
            return dict(plan, action="apply", status="applied", effective=self.effective(snapshot["desired"]), snapshot=STATE)


def human_problem(message):
    translations = {
        "BBR is not available in the running kernel; no modules will be loaded automatically.": "BBR недоступен в текущем ядре. Модули автоматически не загружаются.",
        "Managed target already belongs to another configuration; refusing replacement.": "Файл профиля принадлежит другой конфигурации; замена запрещена.",
        "An existing transaction snapshot requires rollback or inspection first.": "Есть сохранённая копия предыдущего применения. Сначала выполните откат или проверьте её.",
        "Invalid transaction snapshot": "Сохранённая копия повреждена или имеет неподдерживаемый формат.",
        "Runtime changed after transaction; refusing to overwrite administrator changes": "Настройки изменены после применения профиля. Чужие изменения не перезаписаны.",
        "Managed file changed after transaction; refusing to overwrite administrator changes": "Файл профиля изменён после применения. Чужие изменения не перезаписаны.",
        "Apply failed; original runtime and file restored": "Применение не удалось. Исходные настройки и файл восстановлены.",
    }
    for prefix, replacement in (
        ("Potential later override: ", "Возможное переопределение другим файлом: "),
        ("Rollback incomplete; snapshot retained at ", "Откат не завершён. Копия сохранена: "),
        ("Apply failed and rollback incomplete; snapshot retained at ", "Применение и откат не завершены. Копия сохранена: "),
    ):
        if message.startswith(prefix):
            return replacement + message[len(prefix):]
    return translations.get(message, message)


def human_report(report, details=False):
    if report.get("status") == "error":
        return "Ошибка профиля: " + human_problem(report["error"])
    if report.get("adaptive"):
        memory = report["memory"]
        lines = ["Адаптивный сетевой профиль", "RAM: %.0f MiB; уровень %s (swap не учитывается)" %
                 (memory["effective_bytes"] / 1024**2, memory["tier"]),
                 "Параметр | Сейчас | Выбрано"]
        for key, value in report["desired"].items():
            lines.append(key + " | " + report.get("effective", report["current"]).get(key, "—") + " | " + value)
        lines.append("Состояние: " + {"unchanged": "уже применено, исходная копия сохранена", "applied": "применено",
                     "prepared": "модули подготовлены"}.get(report.get("status"), "готово" if report["ready"] else "требуется подготовка или устранение конфликта"))
        lines.extend("  • " + human_problem(item) for item in report["blockers"])
        lines.extend("  • Требуется prepare --adaptive: " + item for item in report["needs_prepare"])
        lines.extend("  • " + item for item in report["warnings"])
        lines.append("Маршрутизация, rp_filter, текущие очереди интерфейсов и глобальные лимиты файлов не меняются.")
        return "\n".join(lines)
    values = report.get("current", report.get("effective", {}))
    lines = ["TCP:                  " + values.get("net.ipv4.tcp_congestion_control", "без изменения"),
             "Очередь по умолчанию:  " + values.get("net.core.default_qdisc", "без изменения")]
    if report["action"] == "plan":
        matches = report["current"] == report["desired"]
        lines += ["Состояние:            " + ("уже соответствует BBR/fq" if matches else "отличается от BBR/fq"),
                  "Применение:           " + ("доступно" if report["ready"] else "недоступно"),
                  "План изменений:       сохранить BBR/fq в отдельный файл X-Manager"]
        if matches:
            lines.append("Повторное включение BBR не требуется. Применение добавит управляемый файл и копию для отката.")
        for problem in report["blockers"]:
            lines.append("  • " + human_problem(problem))
        # Show only relevant later declarations in the brief view; keep every
        # source/line available in details without changing conflict detection.
        sources = {}
        for item in report["declarations"]:
            if item["potential_later_override"]:
                sources.setdefault(item["file"], []).append(item)
        if sources:
            lines.append("Дополнительные конфигурации:")
            for name, entries in sources.items():
                match = all(item["value"] == report["desired"][item["key"]] for item in entries)
                lines.append("  " + Path(name).name + " — " + ("значения совпадают" if match else "есть отличающиеся значения"))
        if details:
            lines += ["", "Файл X-Manager: " + report["file"], "Найденные объявления:"]
            for item in report["declarations"]:
                lines.append(f"  {item['file']}:{item['line']} — {item['key']} = {item['value']}")
            lines += ["Содержимое предлагаемого файла:", report["file_preview"].rstrip()]
    else:
        lines.append("Результат: " + ("профиль применён" if report["action"] == "apply" else "предыдущие настройки восстановлены"))
        if report.get("snapshot"):
            lines.append("Копия для отката: " + report["snapshot"])
    lines.append("Настройки относятся к новым TCP-соединениям и новым очередям. Очереди действующих интерфейсов не меняются.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "prepare", "apply", "rollback"))
    parser.add_argument("--adaptive", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--human", action="store_true")
    parser.add_argument("--details", action="store_true")
    args = parser.parse_args()
    if args.action != "plan" and os.geteuid() != 0:
        parser.error("apply/rollback require root")
    try:
        report = getattr(Profile(), args.action)(**({"adaptive": args.adaptive} if args.action != "rollback" else {}))
    except (OSError, ValueError, RuntimeError) as error:
        report = {"status": "error", "error": str(error)}
        print(human_report(report) if args.human and not args.json else json.dumps(report, ensure_ascii=False))
        return 1
    print(human_report(report, args.details) if args.human and not args.json else json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ready", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
