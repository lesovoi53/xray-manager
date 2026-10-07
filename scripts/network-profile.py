#!/usr/bin/env python3
"""Explicit BBR/fq default profile with preview, effective verification and rollback.

Does not change active interface qdiscs, forwarding, reverse-path filtering,
buffers or service limits. No module loading, network restart or reboot.
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

    def effective(self):
        values = {}
        for key in VALUES:
            value = self.read("/proc/sys/" + key.replace(".", "/")).strip()
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value):
                raise ValueError("Unexpected effective sysctl value: " + key)
            values[key] = value
        return values

    def source_declarations(self):
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
                for target in VALUES:
                    if fnmatch.fnmatchcase(target, key):
                        value = match[2].strip()
                        # Selected keys are scalar kernel identifiers, never config blobs.
                        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value):
                            value = "<non-scalar declaration>"
                        records.append({"key": target, "value": value, "file": name, "line": line_no,
                                        "potential_later_override": path.name >= Path(CONFIG).name or
                                        name == "/etc/sysctl.conf"})
        return records

    def plan(self):
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
        for key in VALUES:
            self.run("sysctl", "-w", key + "=" + values[key])
        if self.effective() != values:
            raise RuntimeError("Effective sysctl verification failed")

    def restore(self, snapshot):
        # Try every key even if one write fails, then restore persistence. Keep a
        # retryable snapshot if any step failed (including the effective read).
        errors = []
        for key in VALUES:
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
            if self.effective() != snapshot["before"]:
                errors.append(RuntimeError("Effective rollback verification failed"))
        except (OSError, ValueError, RuntimeError) as error:
            errors.append(error)
        if errors:
            snapshot["phase"] = "rollback_failed"
            self.save_snapshot(snapshot)
            raise RuntimeError("Rollback incomplete; snapshot retained at " + STATE) from errors[0]
        self.path(STATE).unlink()

    def apply(self):
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
            snapshot = json.loads(self.read(STATE))
            if (snapshot.get("schema_version") != 1 or snapshot.get("desired") != VALUES or
                    snapshot.get("managed_content") != CONTENT or
                    set(snapshot.get("before", {})) != set(VALUES) or
                    any(not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value)
                        for value in snapshot["before"].values())):
                raise ValueError("Invalid transaction snapshot")
            current = self.effective()
            if any(current[key] not in (VALUES[key], snapshot["before"][key]) for key in VALUES):
                raise ValueError("Runtime changed after transaction; refusing to overwrite administrator changes")
            config = self.path(CONFIG)
            file_now = self.read(CONFIG) if config.exists() else None
            prior = snapshot.get("file_before")
            file_before = prior["content"] if prior is not None else None
            recoverable = snapshot.get("phase") in ("applying", "rollback_failed") and file_now == file_before
            if config.is_symlink() or (file_now != CONTENT and not recoverable):
                raise ValueError("Managed file changed after transaction; refusing to overwrite administrator changes")
            self.restore(snapshot)
            return {"action": "rollback", "status": "restored", "effective": self.effective(), "note": NOTE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "rollback"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.action != "plan" and os.geteuid() != 0:
        parser.error("apply/rollback require root")
    try:
        report = getattr(Profile(), args.action)()
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"status": "error", "error": str(error)}, ensure_ascii=False))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ready", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
