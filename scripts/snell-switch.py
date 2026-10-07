#!/usr/bin/env python3
"""Select one installed local Snell server; preserve configuration and rollback intent."""
import argparse
import base64
import configparser
from contextlib import contextmanager, nullcontext
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile

SELECTION = "/etc/x-manager/snell-active.json"
UNITS = ("snell.service",) + tuple("snell6@%d.service" % i for i in range(1, 9))


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


control = helper("service-control")


def command(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Command timed out: " + args[0]) from None
    if result.returncode:
        # A core error may contain a PSK or a configuration excerpt.
        error = RuntimeError("Command failed: " + args[0] + " " + args[1])
        error.returncode = result.returncode
        raise error
    return result.stdout.strip()


def selection(version, slot=None, endpoint_id=None):
    if type(version) is not int or version not in (5, 6):
        raise ValueError("Snell server version must be 5 or 6")
    if version == 5:
        if slot is not None or endpoint_id is not None:
            raise ValueError("Snell v5 has no endpoint slot")
        unit = "snell.service"
    else:
        if str(slot) not in tuple(str(i) for i in range(1, 9)):
            raise ValueError("Snell v6 slot must be 1..8")
        if not isinstance(endpoint_id, str) or not re.fullmatch(r"[0-9a-f]{32}", endpoint_id):
            raise ValueError("Invalid selected endpoint identity")
        slot = str(slot)
        unit = "snell6@" + slot + ".service"
    return dict(format=1, version=version, slot=slot, unit=unit, endpoint_id=endpoint_id)


def read_selection(root=Path("/")):
    """Missing marker means legacy behavior; invalid state must fail closed."""
    path = Path(root) / SELECTION.lstrip("/")
    if path.is_symlink():
        raise ValueError("Selection marker must not be a symlink")
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid Snell selection marker")
    expected = selection(value.get("version"), value.get("slot"), value.get("endpoint_id"))
    if value != expected or type(value.get("format")) is not int:
        raise ValueError("Invalid Snell selection marker")
    return value


@contextmanager
def deadline(seconds):
    """Bound the complete authenticated probe, including repeated socket reads."""
    if not hasattr(signal, "SIGALRM"):
        raise RuntimeError("Snell readiness probing requires Linux")
    def expired(signum, frame):
        raise TimeoutError("Snell readiness probe timed out")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


class LockedLifecycle(control.Controller):
    """Used only while the caller holds the original Controller.lock()."""
    _snell_switch_authorized = True

    def lock(self):
        return nullcontext()


class Controller:
    def __init__(self, root=Path("/"), run=command, probe=None):
        self.root, self.run, self.probe = Path(root), run, probe
        self.lifecycle = control.Controller(self.root, run)

    def path(self, absolute):
        return self.root / absolute.lstrip("/")

    @contextmanager
    def lock(self):
        # Same ordering as endpoint editing. Never nest lifecycle.change's flock.
        directory = self.path("/run/lock")
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "x-manager-snell6.lock").open("a") as stream:
            if os.name == "posix":
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX)
            with self.lifecycle.lock():
                yield

    def status(self):
        return {"selected": read_selection(self.root),
                "units": [self.lifecycle.status(unit) for unit in UNITS]}

    def prepare(self, version, slot):
        endpoints = helper("snell6-endpoints")
        if version == 5:
            chosen = selection(version, slot)
            for name in ("/etc/snell/snell-server.conf", "/usr/local/bin/snell-server"):
                if not self.path(name).is_file():
                    raise ValueError("Snell v5 is not installed: " + name)
            parser = configparser.ConfigParser(interpolation=None)
            parser.read(self.path("/etc/snell/snell-server.conf"), encoding="utf-8")
            section = parser["snell-server"]
            host, separator, port = section.get("listen", "").rpartition(":")
            if not separator or not port.isdigit() or not 1 <= int(port) <= 65535 or not section.get("psk"):
                raise ValueError("Snell v5 requires a valid listener and shared PSK")
            obfs = section.get("obfs", "off").strip()
            if obfs not in ("off", "none", "http", "tls"):
                raise ValueError("Unsupported Snell v5 obfuscation")
            value = dict(version=4, endpoint_id=None, port=int(port), psk=section["psk"],
                         probe_url="https://example.com/", routing="direct",
                         obfs_mode="none" if obfs == "off" else obfs,
                         obfs_host=section.get("obfs-host", "").strip())
            core = self.path(endpoints.CORE_BASE) / endpoints.CORE_SHA256 / "sing-box"
            if core.exists() and endpoints.digest(core) != endpoints.CORE_SHA256:
                raise ValueError("Pinned readiness core checksum mismatch")
            return chosen, (endpoints, value, core if core.exists() else None)
        if version != 6 or str(slot) not in tuple(str(i) for i in range(1, 9)):
            raise ValueError("Select server version 5 or version 6 with slot 1..8")
        manager = endpoints.Manager(self.root, self.run)
        value = manager.load(slot)
        if value.get("users") or value.get("userkey"):
            raise ValueError("Selected Snell endpoint must use a shared PSK without user keys")
        directory = manager.directory(slot)
        if (directory / "config.json").read_bytes() != endpoints.encoded(endpoints.render(value)):
            raise ValueError("Endpoint configuration was edited externally")
        if endpoints.digest(directory / "core") != value["core_sha256"]:
            raise ValueError("Endpoint core checksum mismatch")
        self.run(str(directory / "core"), "check", "-c", str(directory / "config.json"))
        return selection(version, slot, value["endpoint_id"]), (endpoints, value, directory / "core")

    def verify(self, chosen, endpoint):
        if self.lifecycle.show(chosen["unit"]).get("ActiveState") != "active":
            raise RuntimeError("Selected Snell service is not active")
        for unit in UNITS:
            if unit != chosen["unit"] and self.lifecycle.show(unit).get("ActiveState") not in ("inactive", "failed", None):
                raise RuntimeError("Another Snell service remains active: " + unit)
        if endpoint:
            module, value, core = endpoint
            if self.probe is not None:
                self.probe(value, core, self.run)
            else:
                with deadline(60):
                    if core is None:
                        with socket.create_connection(("127.0.0.1", value["port"]), timeout=3):
                            pass
                    else:
                        module.gateway_check(value)
                        module.endpoint_probe(value, core, self.run)
            return "authenticated" if core is not None else "listener-only"

    def snapshot(self, units):
        paths = [self.lifecycle.state_path, self.path(SELECTION)]
        for unit in units:
            self.lifecycle.check_owned(unit)
            paths.extend((*self.lifecycle.markers(unit), self.lifecycle.dropin(unit)))
        files = {}
        for path in paths:
            if path.is_symlink():
                raise ValueError("Refusing foreign symlink: " + str(path))
            files[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        return files

    def backup(self, before, files, firewall=None):
        parent = self.path("/var/backups/x-manager-snell-switch")
        if parent.is_symlink():
            raise ValueError("Backup directory must not be a symlink")
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        parent.chmod(0o700)
        directory = Path(tempfile.mkdtemp(prefix="switch-", dir=parent))
        directory.chmod(0o700)
        configs = [self.path("/etc/snell/snell-server.conf")]
        configs.extend(self.path("/etc/snell6/endpoints").glob("[1-8]/*.json"))
        values = dict(files)
        for path in configs:
            if path.is_file() and not path.is_symlink():
                values[path] = path.read_bytes(), path.stat().st_mode & 0o777
        record = {"format": 1, "units": before, "files": {
            "/" + path.relative_to(self.root).as_posix(): None if old is None else
            {"mode": old[1], "base64": base64.b64encode(old[0]).decode("ascii")}
            for path, old in values.items()}}
        if firewall:
            record["firewall"] = {"endpoint_id": firewall[1]["endpoint_id"], "present": firewall[2]}
        control.atomic_write(directory / "before.json", json.dumps(record, sort_keys=True, indent=2) + "\n")
        return str(directory)

    def rollback(self, touched, before, files):
        # Stop every changed unit before removing inhibits or restarting old ones.
        # If stop fails, keep inhibits rather than risking simultaneous servers.
        for unit in touched:
            self.lifecycle.ctl("stop", unit)
        for path, original in files.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                data, mode = original
                control.atomic_write(path, data.decode("utf-8"), mode)
        self.lifecycle.ctl("daemon-reload")
        for unit in touched:
            state = before[unit]
            enabled = state["UnitFileState"]
            if enabled in ("enabled", "enabled-runtime"):
                args = ("enable", "--runtime", unit) if enabled == "enabled-runtime" else ("enable", unit)
                self.lifecycle.ctl(*args)
            elif enabled == "disabled":
                self.lifecycle.ctl("disable", unit)
        for unit in touched:
            if before[unit]["ActiveState"] == "active":
                self.lifecycle.ctl("start", unit)
                if self.lifecycle.show(unit).get("ActiveState") != "active":
                    raise RuntimeError("Could not restore previously active service: " + unit)

    def switch(self, version, slot=None):
        with self.lock():
            previous = read_selection(self.root)
            self.lifecycle.read()  # Validate before making any changes.
            conflicts = [s["unit"] for s in self.lifecycle.conflicts() if s["conflict"]]
            if conflicts:
                raise ValueError("Active external watchdog prevents safe switching: " + ", ".join(conflicts))
            chosen, endpoint = self.prepare(version, slot)
            before = {unit: self.lifecycle.status(unit) for unit in UNITS}
            target = before[chosen["unit"]]
            if target.get("LoadState") != "loaded" or target.get("UnitFileState", "").startswith("masked"):
                raise ValueError("Selected service is not installed or is administrator-masked")
            installed = [unit for unit, state in before.items() if state.get("LoadState") in ("loaded", "masked")]
            for unit in installed:
                state = before[unit]
                if state.get("ActiveState") not in ("active", "inactive", "failed"):
                    raise ValueError("Wait for service transition to finish: " + unit)
                if state.get("UnitFileState") not in ("enabled", "enabled-runtime", "disabled", "static", "indirect", "masked", "masked-runtime"):
                    raise ValueError("Unsupported service installation state: " + unit)
            files = self.snapshot(installed)
            lifecycle = LockedLifecycle(self.root, self.run)
            touched = []
            firewall = None
            if version == 6:
                endpoints, value, core = endpoint
                def firewall_run(*args):
                    try:
                        return self.run(*args)
                    except (RuntimeError, OSError) as failure:
                        error = endpoints.Error("Snell firewall command failed")
                        error.returncode = getattr(failure, "returncode", None)
                        raise error from failure
                manager = endpoints.Manager(self.root, firewall_run)
                firewall = (manager, value, manager.firewall_exists(value))
            backup = self.backup(before, files, firewall)
            try:
                for unit in installed:
                    if unit == chosen["unit"]:
                        continue
                    state = before[unit]
                    if state["off"] and state["ActiveState"] in ("inactive", "failed") and state["UnitFileState"] not in ("enabled", "enabled-runtime"):
                        continue
                    touched.append(unit)
                    lifecycle.change("off", unit)
                if not (target["ActiveState"] == "active" and target["UnitFileState"] == "enabled"
                        and not target["off"] and not target["stopped"]):
                    touched.append(chosen["unit"])
                    lifecycle.change("on", chosen["unit"])
                if firewall:
                    manager, value, present = firewall
                    # ExecStartPre sees the old committed selection until the
                    # switch succeeds. Apply this endpoint's own saved rule here.
                    manager.firewall(value, value["firewall_open"])
                verification = self.verify(chosen, endpoint)
                if previous != chosen:
                    control.atomic_write(self.path(SELECTION), json.dumps(chosen, sort_keys=True, indent=2) + "\n", 0o644)
                return {"changed": bool(touched) or previous != chosen, "selected": chosen,
                        "verification": verification, "backup": backup}
            except Exception as failure:
                try:
                    self.rollback(touched, before, files)
                    if firewall:
                        manager, value, present = firewall
                        manager.firewall(value, present)
                except Exception as rollback_error:
                    raise RuntimeError("Snell switch failed; rollback incomplete; inspect service state before retrying") from rollback_error
                raise RuntimeError("Snell switch failed; previous lifecycle state restored") from failure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("switch", "status"))
    parser.add_argument("--version", type=int, choices=(5, 6))
    parser.add_argument("--slot", choices=tuple(str(i) for i in range(1, 9)))
    args = parser.parse_args(argv)
    controller = Controller()
    if args.action == "status":
        result = controller.status()
    else:
        if os.geteuid() != 0:
            raise ValueError("Root privileges required")
        result = controller.switch(args.version, args.slot)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("Snell switch error: " + str(error), file=sys.stderr)
        sys.exit(2)
