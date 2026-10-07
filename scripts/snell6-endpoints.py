#!/usr/bin/env python3
"""Opt-in Snell v6 endpoints. V5, panel configuration and shared DB files stay intact.

Explicit Snell v6 endpoints. JSON changes arrive on stdin.
Rollback restores this endpoint's files/service and owned firewall rule; SQLite
is rolled back transactionally, never replaced with a stale whole-database copy.
"""
import argparse
from contextlib import contextmanager
import datetime
import hashlib
import getpass
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from urllib.parse import urlsplit
from urllib.request import urlopen
import uuid

VERSION = "1.14.1-extended-2.7.2"
CORE_SHA256 = "187965235a83a462aa10291cfab561d0caed2fde90a608e6899b17aed9e01ea8"
ARCHIVE_SHA256 = "e4606cc7e3ee19885b5c16ad4ec8e28c8b3bacbc31949f93018cd5c77883b28b"
CORE_ASSET = "snell6-amd64.tar.gz"
BASE = "/etc/snell6/endpoints"
CORE_BASE = "/usr/local/lib/x-manager/snell6"
FILES = ("endpoint.json", "config.json", "core")


class Error(Exception):
    pass


def load_helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        # Core diagnostics may contain configuration excerpts; never print them.
        error = Error("Command failed: " + args[0] + " " + args[1])
        error.returncode = result.returncode
        raise error
    return result.stdout.strip()


def slot_number(slot):
    if str(slot) not in tuple(str(i) for i in range(1, 9)):
        raise Error("Endpoint slot must be 1..8")
    return str(slot)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate(value):
    expected = {"format", "endpoint_id", "slot", "version", "mode", "name", "psk", "port",
                "listen", "routing", "socks_port", "server_host", "core_sha256", "probe_url", "firewall_open"}
    if set(value) != expected or value["format"] != 1:
        raise Error("Unsupported or incomplete endpoint identity")
    slot_number(value["slot"])
    if not re.fullmatch(r"[0-9a-f]{32}", value["endpoint_id"]):
        raise Error("Invalid stable endpoint identity")
    if value["version"] != 6 or value["mode"] not in ("default", "unshaped", "unsafe-raw"):
        raise Error("Snell v6 mode must be default, unshaped or unsafe-raw")
    for field in ("name", "psk", "server_host"):
        if not isinstance(value[field], str) or not value[field] or any(ord(c) < 32 for c in value[field]):
            raise Error("Invalid endpoint " + field)
    if value["listen"] not in ("0.0.0.0", "127.0.0.1"):
        raise Error("Only qualified IPv4 listening addresses are supported")
    if type(value["firewall_open"]) is not bool:
        raise Error("firewall_open must be true or false")
    if type(value["port"]) is not int or not 1024 <= value["port"] <= 65535 or value["port"] in (443, 8443):
        raise Error("New endpoint requires an allowed unprivileged port")
    if value["routing"] not in ("xray", "direct"):
        raise Error("Routing must explicitly be xray or direct")
    if type(value["socks_port"]) is not int or not 1 <= value["socks_port"] <= 65535:
        raise Error("Invalid SOCKS gateway port")
    if not re.fullmatch(r"[0-9a-f]{64}", value["core_sha256"]):
        raise Error("Invalid pinned core digest")
    parsed = urlsplit(value["probe_url"])
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise Error("Readiness probe requires an HTTPS URL without credentials or fragment")
    if any(ord(c) < 33 for c in value["probe_url"]):
        raise Error("Invalid readiness URL")
    load_helper("snell-subscriptions").uri(value, value["server_host"])
    return value


def render(value):
    validate(value)
    outbound = ({"type": "socks", "tag": "upstream", "server": "127.0.0.1",
                 "server_port": value["socks_port"], "version": "5"}
                if value["routing"] == "xray" else {"type": "direct", "tag": "upstream"})
    config = {"log": {"level": "error"}, "inbounds": [
        {"type": "snell", "listen": value["listen"], "listen_port": value["port"],
         "version": 6, "mode": value["mode"], "psk": value["psk"]}],
        "outbounds": [outbound], "route": {"final": "upstream"}}
    return config


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def atomic(path, data, mode, gid=0):
    if path.is_symlink():
        raise Error("Refusing to replace foreign symlink")
    descriptor, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), 0, gid)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def recv_exact(sock, size):
    result = b""
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise Error("SOCKS gateway closed its response")
        result += part
    return result


def socks_request(sock, command, host, port):
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise Error("SOCKS5 no-auth gateway is required")
    address = host.encode("idna")
    sock.sendall(bytes([5, command, 0, 3, len(address)]) + address + port.to_bytes(2, "big"))
    header = recv_exact(sock, 4)
    if header[:3] != b"\x05\x00\x00":
        raise Error("SOCKS5 gateway rejected request")
    size = {1: 4, 4: 16}.get(header[3])
    if header[3] == 3:
        size = recv_exact(sock, 1)[0]
    if size is None:
        raise Error("Invalid SOCKS5 reply address")
    recv_exact(sock, size)
    return int.from_bytes(recv_exact(sock, 2), "big")


def gateway_check(value):
    if value["routing"] == "xray":
        with socket.create_connection(("127.0.0.1", value["socks_port"]), timeout=3) as sock:
            if not socks_request(sock, 3, "0.0.0.0", 0):
                raise Error("SOCKS5 UDP ASSOCIATE did not return a relay port")


def endpoint_probe(value, core, runner=run):
    """A real authenticated Snell TCP roundtrip through the configured outbound."""
    for attempt in range(40):
        try:
            with socket.create_connection(("127.0.0.1", value["port"]), timeout=.2):
                break
        except OSError:
            time.sleep(.1)
    else:
        raise Error("Snell endpoint did not open its listener")
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    config = {"log": {"level": "error"}, "inbounds": [
        {"type": "socks", "listen": "127.0.0.1", "listen_port": port}], "outbounds": [
        {"type": "snell", "server": "127.0.0.1", "server_port": value["port"],
         "version": value.get("version", 6), "psk": value["psk"], "reuse": False}]}
    if value.get("version", 6) == 6:
        config["outbounds"][0]["mode"] = value["mode"]
    else:
        config["outbounds"][0]["obfs_mode"] = value.get("obfs_mode", "none")
        if value.get("obfs_host"):
            config["outbounds"][0]["obfs_host"] = value["obfs_host"]
    with tempfile.TemporaryDirectory(prefix="snell6-probe-") as temporary:
        candidate = Path(temporary) / "client.json"
        candidate.write_bytes(encoded(config))
        candidate.chmod(0o600)
        runner(str(core), "check", "-c", str(candidate))
        with open(os.devnull, "wb") as silent:
            process = subprocess.Popen([str(core), "run", "-c", str(candidate)], stdout=silent, stderr=silent)
        try:
            for attempt in range(40):
                if process.poll() is not None:
                    raise Error("Snell readiness client failed")
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=3)
                    break
                except OSError:
                    time.sleep(.1)
            else:
                raise Error("Snell readiness client did not listen")
            parsed = urlsplit(value["probe_url"])
            with sock:
                socks_request(sock, 1, parsed.hostname, parsed.port or 443)
                with ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname) as secure:
                    path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
                    request = "GET " + path + " HTTP/1.1\r\nHost: " + parsed.netloc + "\r\nConnection: close\r\n\r\n"
                    secure.sendall(request.encode("ascii"))
                    response = b""
                    while b"\r\n" not in response and len(response) < 4096:
                        chunk = secure.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                    if not re.match(rb"HTTP/1\.[01] 2[0-9][0-9] ", response):
                        raise Error("Snell readiness HTTPS request did not return HTTP 2xx")
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


class Manager:
    def __init__(self, root=Path("/"), runner=run, probe=endpoint_probe, gateway=gateway_check):
        self.root, self.run, self.probe, self.gateway = Path(root), runner, probe, gateway

    def path(self, value):
        return self.root / value.lstrip("/")

    def directory(self, slot):
        return self.path(BASE) / slot_number(slot)

    def load(self, slot):
        data = validate(json.loads((self.directory(slot) / "endpoint.json").read_text()))
        if str(data["slot"]) != slot_number(slot):
            raise Error("Endpoint identity belongs to another slot")
        return data

    def lifecycle(self):
        return load_helper("service-control").Controller(self.root, self.run)

    @contextmanager
    def lock(self):
        import fcntl
        directory = self.path("/run/lock")
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "x-manager-snell6.lock").open("a") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            with self.lifecycle().lock():
                yield

    def service(self, slot):
        return "snell6@" + slot_number(slot) + ".service"

    def state(self, slot):
        output = self.run("systemctl", "show", self.service(slot), "--property=LoadState,ActiveState,UnitFileState")
        return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)

    def account(self):
        import pwd
        try:
            user = pwd.getpwnam("snell6")
        except KeyError:
            self.run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
                     "--shell", "/usr/sbin/nologin", "snell6")
            user = pwd.getpwnam("snell6")
        if user.pw_uid == 0:
            raise Error("Snell6 must run as its own non-root user")
        return user.pw_gid

    def install_core(self, source=None):
        destination = self.path(CORE_BASE) / CORE_SHA256 / "sing-box"
        if destination.exists():
            if digest(destination) != CORE_SHA256:
                raise Error("Installed pinned Snell6 core has changed")
            return destination
        with tempfile.TemporaryDirectory(prefix="snell6-core-") as temporary:
            candidate = Path(source) if source else Path(temporary) / "sing-box"
            if source is None:
                archive = Path(temporary) / "core.tar.gz"
                manifest = json.loads(Path(__file__).resolve().parent.parent.joinpath("components.json").read_text())
                if manifest["sha256"].get(CORE_ASSET) != ARCHIVE_SHA256:
                    raise Error("Release manifest does not match pinned Snell6 archive")
                load_helper("release-assets").fetch(manifest, CORE_ASSET, archive,
                                                   os.environ.get("XM_RELEASE_ASSET_DIR"))
                if digest(archive) != ARCHIVE_SHA256:
                    raise Error("Pinned Snell6 archive checksum mismatch")
                with tarfile.open(archive) as bundle:
                    binaries = [member for member in bundle.getmembers()
                                if member.isfile() and Path(member.name).name == "sing-box"]
                    if len(binaries) != 1:
                        raise Error("Archive must contain exactly one regular sing-box binary")
                    with bundle.extractfile(binaries[0]) as incoming, candidate.open("wb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
            if digest(candidate) != CORE_SHA256:
                raise Error("Pinned Snell6 binary checksum mismatch")
            with candidate.open("rb") as incoming:
                header = incoming.read(20)
            if header[:5] != b"\x7fELF\x02" or header[18:20] != b"\x3e\x00":
                raise Error("Snell6 core must be ELF Linux amd64")
            for parent in (self.path("/usr/local/lib/x-manager"), self.path(CORE_BASE), destination.parent):
                if not parent.exists():
                    parent.mkdir(mode=0o755, parents=True)
                    parent.chmod(0o755)
            atomic(destination, candidate.read_bytes(), 0o755)
        return destination

    def free_port(self, requested=None, except_slot=None):
        reserved = {self.load(i)["port"] for i in range(1, 9)
                    if str(i) != str(except_slot) and (self.directory(i) / "endpoint.json").exists()}
        v5 = self.path("/etc/snell/snell-server.conf")
        if v5.exists():
            match = re.search(r"(?m)^listen\s*=.*:(\d+)\s*$", v5.read_text())
            if match:
                reserved.add(int(match[1]))
        for port in ([requested] if requested is not None else range(20000, 65536)):
            if type(port) is not int or not 1024 <= port <= 65535 or port in (443, 8443) or port in reserved:
                continue
            sockets = []
            try:
                for family, kind in ((socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET, socket.SOCK_DGRAM)):
                    sock = socket.socket(family, kind)
                    sockets.append(sock)
                    sock.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
            finally:
                for sock in sockets:
                    sock.close()
        raise Error("Requested endpoint port is occupied, reserved or forbidden")

    def firewall_rule(self, value):
        return ["-p", "tcp", "--dport", str(value["port"]), "-m", "comment", "--comment",
                "XM_SNELL6_" + value["endpoint_id"], "-j", "ACCEPT"]

    def firewall_exists(self, value):
        try:
            self.run("iptables", "-w", "-C", "INPUT", *self.firewall_rule(value))
            return True
        except Error as error:
            if getattr(error, "returncode", None) != 1:
                raise
            return False

    def firewall(self, value, present):
        exists = self.firewall_exists(value)
        if exists != present:
            self.run("iptables", "-w", "-I" if present else "-D", "INPUT", *self.firewall_rule(value))

    def ensure_firewall(self, slot):
        # Called synchronously by ExecStartPre while the installer may hold its
        # lock. Metadata replacement is atomic; iptables has its own -w lock.
        value = self.load(slot)
        if self.lifecycle().allowed(self.service(slot)):
            self.firewall(value, value["firewall_open"])

    def apply(self, slot, changes=None, create=False, source=None, db_path=None, prepare_only=False):
        slot = slot_number(slot)
        changes = changes or {}
        if set(changes) - {"name", "psk", "port", "mode", "listen", "routing", "socks_port", "server_host", "probe_url", "firewall_open"}:
            raise Error("Unsupported endpoint setting; QUIC and implicit v5 migration are not available")
        with self.lock():
            directory = self.directory(slot)
            identity = directory / "endpoint.json"
            previous = self.load(slot) if identity.exists() else None
            if previous is None and not create:
                raise Error("Endpoint is absent; explicit create is required")
            if previous is None and directory.exists() and any(directory.iterdir()):
                raise Error("Refusing to adopt an unregistered endpoint directory")
            if previous is not None and (directory / "config.json").read_bytes() != encoded(render(previous)):
                raise Error("Endpoint configuration was edited externally; resolve conflict first")
            if previous is not None and (not (directory / "core").is_symlink() or
                    (directory / "core").resolve() != self.path(CORE_BASE) / previous["core_sha256"] / "sing-box"):
                raise Error("Endpoint core link changed externally")
            if previous:
                value = dict(previous, **changes)
            else:
                gateways = self.path("/etc/x-manager/gateways.env")
                match = re.search(r"(?m)^XRAY_SOCKS_PORT=(\d+)\s*$", gateways.read_text()) if gateways.exists() else None
                value = dict(format=1, endpoint_id=uuid.uuid4().hex, slot=slot, version=6,
                             mode="default", name="Snell-v6-" + slot, psk=secrets.token_urlsafe(32),
                             port=changes.get("port", self.free_port(except_slot=slot)), listen="0.0.0.0",
                             routing="xray", socks_port=int(match[1]) if match else 10808,
                             server_host="", core_sha256=CORE_SHA256, probe_url="https://example.com/", firewall_open=True)
                value.update(changes)
            value["core_sha256"] = CORE_SHA256
            previous_firewall = self.firewall_exists(previous) if previous else False
            if previous and "firewall_open" not in changes:
                value["firewall_open"] = previous_firewall
            validate(value)
            needs_restart = (previous is None or encoded(render(previous)) != encoded(render(value))
                             or previous["core_sha256"] != value["core_sha256"])
            if previous and needs_restart and previous_firewall != previous["firewall_open"]:
                raise Error("Firewall rule differs from saved intent; run update to preserve its current state before changing transport")
            live = self.state(slot)
            if live.get("LoadState") not in ("loaded", "masked"):
                raise Error("Install the managed snell6@.service template before creating an endpoint")
            if previous is None or value["port"] != previous["port"]:
                self.free_port(value["port"], slot)
            core = self.install_core(source)
            with tempfile.TemporaryDirectory(prefix="snell6-validate-") as temporary:
                candidate = Path(temporary) / "config.json"
                candidate.write_bytes(encoded(render(value)))
                candidate.chmod(0o600)
                self.run(str(core), "check", "-c", str(candidate))
            if previous == value:
                return {"changed": False, "slot": slot, "endpoint_id": value["endpoint_id"]}
            lifecycle = self.lifecycle()
            should_start = (not prepare_only and previous is None or live.get("ActiveState") == "active") and lifecycle.allowed(self.service(slot))
            should_start = should_start and live.get("LoadState") != "masked" and not live.get("UnitFileState", "").startswith("masked")
            if should_start:
                self.gateway(value)
            firewall_before = [(value, self.firewall_exists(value))]
            if previous and previous["port"] != value["port"]:
                firewall_before.append((previous, self.firewall_exists(previous)))
            gid = self.account()
            backup_parent = self.path("/var/backups")
            backup_parent.mkdir(parents=True, exist_ok=True)
            backup = Path(tempfile.mkdtemp(prefix="x-manager-snell6-", dir=backup_parent))
            backup.chmod(0o700)
            snapshots = {}
            for name in FILES:
                path = directory / name
                if path.is_symlink():
                    if name != "core":
                        raise Error("Endpoint metadata cannot be a symlink")
                    snapshots[name] = {"link": os.readlink(path)}
                elif path.exists():
                    snapshots[name] = {"mode": path.stat().st_mode & 0o777, "gid": path.stat().st_gid}
                    shutil.copyfile(path, backup / name)
                else:
                    snapshots[name] = None
            (backup / "state.json").write_bytes(encoded({"slot": slot, "service": live, "files": snapshots}))
            db = sqlite3.connect(Path(db_path).as_uri() + "?mode=rw", uri=True, timeout=15) if db_path else None
            touched = False
            try:
                if db:
                    db.execute("BEGIN IMMEDIATE")
                    load_helper("snell-subscriptions").synchronize(db, value, value["server_host"], endpoint_id=value["endpoint_id"])
                # A separate UID/group is used; v5's owner-match routing never applies.
                directory.mkdir(parents=True, exist_ok=True)
                for parent in (self.path("/etc/snell6"), self.path(BASE), directory):
                    os.chown(parent, 0, gid)
                    parent.chmod(0o750)
                touched = True
                if needs_restart and live.get("ActiveState") == "active":
                    self.run("systemctl", "stop", self.service(slot))
                atomic(directory / "endpoint.json", encoded(value), 0o600)
                atomic(directory / "config.json", encoded(render(value)), 0o640, gid)
                link = directory / ".core-new"
                if link.exists() or link.is_symlink():
                    raise Error("Unexpected endpoint staging link")
                link.symlink_to(core)
                os.replace(link, directory / "core")
                self.run("systemctl", "daemon-reload")
                if (previous is None and not prepare_only and lifecycle.allowed(self.service(slot), enable=True)
                        and live.get("LoadState") != "masked" and not live.get("UnitFileState", "").startswith("masked")):
                    self.run("systemctl", "enable", self.service(slot))
                self.firewall(value, value["firewall_open"])
                if previous and previous["port"] != value["port"]:
                    self.firewall(previous, False)
                if should_start:
                    if needs_restart:
                        self.run("systemctl", "reset-failed", self.service(slot))
                        self.run("systemctl", "start", self.service(slot))
                    self.run("systemctl", "is-active", "--quiet", self.service(slot))
                    self.probe(value, core, self.run)
                (backup / "result.json").write_bytes(encoded({"slot": slot, "running_checked": bool(should_start)}))
                if db:
                    db.commit()
                return {"changed": True, "slot": slot, "endpoint_id": value["endpoint_id"],
                        "running_checked": bool(should_start), "backup": str(backup)}
            except Exception as failure:
                if db:
                    db.rollback()
                if touched:
                    try:
                        if needs_restart:
                            self.run("systemctl", "stop", self.service(slot))
                        if previous is None:
                            self.run("systemctl", "disable", self.service(slot))
                        for name, snapshot in snapshots.items():
                            path = directory / name
                            if path.is_symlink() or name == "core":
                                path.unlink(missing_ok=True)
                            if snapshot is None:
                                path.unlink(missing_ok=True)
                            elif "link" in snapshot:
                                path.symlink_to(snapshot["link"])
                            else:
                                atomic(path, (backup / name).read_bytes(), snapshot["mode"], snapshot["gid"])
                        for original, existed in firewall_before:
                            self.firewall(original, existed)
                        self.run("systemctl", "daemon-reload")
                        if needs_restart and live.get("ActiveState") == "active" and lifecycle.allowed(self.service(slot)):
                            self.run("systemctl", "start", self.service(slot))
                            self.probe(previous, directory / "core", self.run)
                    except Exception:
                        raise Error("Rollback incomplete; preserve private backup: " + str(backup)) from None
                raise Error("Endpoint operation failed; previous state restored; backup: " + str(backup)) from failure
            finally:
                if db:
                    db.close()

    def publish(self, slot, user_id, db_path):
        with self.lock():
            value = self.load(slot)
            self.run("systemctl", "is-active", "--quiet", self.service(slot))
            self.probe(value, self.directory(slot) / "core", self.run)
            generator = load_helper("snell-subscriptions")
            link = generator.uri(value, value["server_host"])
            with sqlite3.connect(Path(db_path).as_uri() + "?mode=rw", uri=True, timeout=15) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT snell_uri FROM users WHERE id=?", (user_id,)).fetchone()
                if row is None:
                    raise Error("Explicit subscription user does not exist")
                lines = (row[0] or "").splitlines()
                changed = link not in lines
                if changed:
                    lines.append(link)
                    db.execute("UPDATE users SET snell_uri=?, revision=revision+1, updated_at=? WHERE id=?",
                               ("\n".join(lines), datetime.datetime.now(datetime.timezone.utc).isoformat(), user_id))
                generator.synchronize(db, value, value["server_host"], bind_user=user_id, endpoint_id=value["endpoint_id"])
                return {"changed": changed, "slot": str(slot), "user": user_id}


def database_path():
    config = Path("/etc/tuna-subscriptions/config.toml")
    if not config.exists():
        return None
    value = Path(tomllib.loads(config.read_text())["database"]["path"])
    if not value.is_absolute():
        value = Path("/var/lib/tuna-subscriptions") / value
    if not value.is_file():
        raise Error("Configured subscription database is missing")
    return value


def choose(title, options):
    print("\n" + title)
    for number, (label, _) in enumerate(options, 1):
        print(f" [{number}] {label}")
    while True:
        answer = input(" [0] Назад\nВыбор: ").strip()
        if answer == "0":
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][1]
        print("Выберите номер из списка.")


def confirm(message):
    return choose(message, [("Применить", True)]) is True


def select_user(database, current=None):
    if database is None:
        raise Error("TUNA database is not configured")
    with sqlite3.connect(Path(database).as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("SELECT id,nickname FROM users ORDER BY nickname,id").fetchall()
    if current:
        if not any(row[0] == current for row in rows):
            raise Error("Subscription user no longer exists")
        return current
    if not rows:
        raise Error("Сначала создайте пользователя TUNA")
    return choose("Пользователь подписки", [(str(name), uid) for uid, name in rows])


def import_link(database, user, link):
    from urllib.parse import parse_qsl, unquote
    try:
        parsed = urlsplit(link)
        fields = parse_qsl(parsed.query, keep_blank_values=True)
        options = dict(fields)
        if (parsed.scheme != "snell" or not parsed.hostname or not parsed.port or not parsed.username
                or options.get("version") != "6" or len(options) != len(fields)
                or any(c.isspace() for c in link)):
            raise ValueError()
        value = dict(version=6, mode=options.get("mode", "default"),
                     port=parsed.port, psk=unquote(parsed.username), name=unquote(parsed.fragment) or "Snell-v6")
        load_helper("snell-subscriptions").uri(value, parsed.hostname, link)
    except Exception:
        raise Error("Некорректная ссылка Snell v6; изменения не сохранены") from None
    with sqlite3.connect(Path(database).as_uri() + "?mode=rw", uri=True) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT snell_uri FROM users WHERE id=?", (user,)).fetchone()
        if row is None:
            raise Error("Subscription user no longer exists")
        lines = (row[0] or "").splitlines()
        if link in lines:
            return False
        lines.append(link)
        db.execute("UPDATE users SET snell_uri=?,revision=revision+1,updated_at=? WHERE id=?",
                   ("\n".join(lines), datetime.datetime.now(datetime.timezone.utc).isoformat(), user))
    return True


def settings_menu(manager, slot):
    while True:
        value = manager.load(slot)
        action = choose("Snell v6 / Настройки", [
            ("Имя: " + value["name"], "name"), ("Порт: " + str(value["port"]), "port"),
            ("Режим: " + value["mode"], "mode"), ("Маршрут: " + value["routing"], "routing"),
            ("Общий PSK (скрыт)", "psk"), ("Адрес в ссылке: " + value["server_host"], "server_host"),
            ("Адрес прослушивания: " + value["listen"], "listen"),
            ("Доступ через firewall: " + ("открыт" if value["firewall_open"] else "закрыт"), "firewall_open")])
        if action is None:
            return
        changes = {}
        if action == "mode":
            mode = choose("Режим на клиенте и сервере должен совпадать", [
                ("default — шифрование и обфускация", "default"),
                ("unshaped — шифрование без обфускации", "unshaped"),
                ("unsafe-raw — без шифрования; PSK не защищает доступ", "unsafe-raw")])
            if mode is None:
                continue
            changes[action] = mode
        elif action == "routing":
            route = choose("Маршрут TCP и UDP", [("SOCKS5 → Xray", "xray"), ("Direct", "direct")])
            if route is None:
                continue
            changes[action] = route
            if route == "xray":
                port = input(f"Порт существующего SOCKS5 [{value['socks_port']}]: ").strip()
                changes["socks_port"] = int(port) if port else value["socks_port"]
        elif action == "listen":
            address = choose("Прослушивание", [("Все IPv4-интерфейсы", "0.0.0.0"), ("Только localhost", "127.0.0.1")])
            if address is None:
                continue
            changes[action] = address
        elif action == "firewall_open":
            changes[action] = not value[action]
        elif action == "psk":
            key_action = choose("Общий ключ", [("Сгенерировать новый", "new"), ("Ввести свой", "input")])
            if key_action is None:
                continue
            changes[action] = secrets.token_urlsafe(32) if key_action == "new" else getpass.getpass("Новый PSK: ")
        else:
            entered = input("Новое значение (Enter — отмена): ").strip()
            if not entered:
                continue
            changes[action] = int(entered) if action == "port" else entered
        if confirm("Применить настройку? Изменение транспорта перезапустит работающий Snell v6; привязанные ссылки обновятся."):
            print(json.dumps(manager.apply(slot, changes, db_path=database_path()), ensure_ascii=False))


def endpoint_menu(manager, slot, current_user=None):
    while True:
        value = manager.load(slot)
        state = manager.state(slot)
        print(f"\nSnell v6 / {value['name']} | {state['ActiveState']} | {value['port']}/TCP | {value['mode']}")
        print("TCP и обычный UDP relay через TCP. Общий PSK.")
        action = choose("Действие", [("Настройки подключения", "settings"),
            ("Показать ссылку (содержит ключ)", "uri"), ("Добавить в подписку TUNA", "publish"),
            ("Активировать Snell v6 вместо Snell v5", "activate"),
            ("Выключить постоянно", "off"), ("Проверить соединение", "probe"),
            ("Обновить закреплённое ядро", "update"), ("Журнал службы", "logs")])
        if action is None:
            return
        if action == "settings":
            settings_menu(manager, slot)
        elif action == "uri":
            print(load_helper("snell-subscriptions").uri(value, value["server_host"]))
        elif action == "publish":
            database = database_path()
            user = select_user(database, current_user)
            if user:
                print(json.dumps(manager.publish(slot, user, database), ensure_ascii=False))
        elif action == "activate":
            if confirm("Остановить другую версию Snell и включить выбранный v6? При ошибке прежнее состояние будет восстановлено."):
                print(json.dumps(load_helper("snell-switch").Controller().switch(6, slot), ensure_ascii=False))
        elif action == "off":
            if confirm("Выключить Snell v6 постоянно? Настройки сохранятся."):
                print(json.dumps(manager.lifecycle().change("off", manager.service(slot)), ensure_ascii=False))
        elif action == "probe":
            manager.run("systemctl", "is-active", "--quiet", manager.service(slot))
            manager.gateway(value)
            manager.probe(value, manager.directory(slot) / "core", manager.run)
            print("Snell → HTTPS: успешно. Удалённый UDP этим запросом не проверяется.")
        elif action == "update":
            print(json.dumps(manager.apply(slot, db_path=database_path()), ensure_ascii=False))
        elif action == "logs":
            subprocess.run(["journalctl", "-u", manager.service(slot), "-n", "30", "--no-pager"], check=True)


def subscription_links(database, user):
    from urllib.parse import parse_qs
    with sqlite3.connect(Path(database).as_uri() + "?mode=ro", uri=True) as db:
        row = db.execute("SELECT snell_uri FROM users WHERE id=?", (user,)).fetchone()
    if row is None:
        raise Error("Subscription user no longer exists")
    return [line for line in (row[0] or "").splitlines()
            if urlsplit(line).scheme == "snell" and parse_qs(urlsplit(line).query).get("version") == ["6"]]


def remove_subscription_link(database, user, link):
    with sqlite3.connect(Path(database).as_uri() + "?mode=rw", uri=True) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT snell_uri FROM users WHERE id=?", (user,)).fetchone()
        if row is None:
            raise Error("Subscription user no longer exists")
        lines = (row[0] or "").splitlines()
        if link not in lines:
            raise Error("Список изменился; выберите ссылку заново")
        db.execute("UPDATE users SET snell_uri=?,revision=revision+1,updated_at=? WHERE id=?",
                   ("\n".join(line for line in lines if line != link), datetime.datetime.now(datetime.timezone.utc).isoformat(), user))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='x_manager_snell_endpoint_links'").fetchone():
            db.execute("DELETE FROM x_manager_snell_endpoint_links WHERE user_id=? AND uri=?", (user, link))


def subscription_menu(manager, user):
    from urllib.parse import unquote
    database = database_path()
    select_user(database, user)
    while True:
        try:
            links = subscription_links(database, user)
            action = choose(f"Snell v6 / Подписка пользователя — ссылок: {len(links)}", [
                ("Показать сохранённые ссылки (содержат ключи)", "show"),
                ("Добавить активное локальное подключение", "local"),
                ("Добавить внешнюю ссылку", "import"),
                ("Удалить ссылку из подписки", "remove")])
            if action is None:
                return
            if action == "show":
                print("\n".join(links) if links else "Ссылок Snell v6 пока нет.")
            elif action == "import":
                link = input("Ссылка Snell v6 (Enter — отмена): ").strip()
                if link:
                    print("Ссылка добавлена." if import_link(database, user, link) else "Эта ссылка уже есть.")
            elif action == "local":
                options = []
                for slot in range(1, 9):
                    if (manager.directory(slot) / "endpoint.json").exists() and manager.state(slot)["ActiveState"] == "active":
                        options.append((manager.load(slot)["name"], str(slot)))
                if not options:
                    print("Активного локального Snell v6 нет. Включение — в разделе «Службы и туннели → Snell».")
                    continue
                slot = choose("Добавить в подписку", options)
                if slot:
                    print(json.dumps(manager.publish(slot, user, database), ensure_ascii=False))
            elif action == "remove":
                if not links:
                    print("Ссылок Snell v6 пока нет.")
                    continue
                link = choose("Удалить только из этой подписки", [
                    (unquote(urlsplit(item).fragment) or urlsplit(item).hostname or "Snell v6", item) for item in links])
                if link and confirm("Удалить выбранную ссылку из подписки? Серверное подключение сохранится."):
                    remove_subscription_link(database, user, link)
                    print("Ссылка удалена из подписки.")
        except (Error, ValueError, OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
            print("Snell v6: " + (str(error) if isinstance(error, (Error, ValueError)) else type(error).__name__))
        except (EOFError, KeyboardInterrupt):
            return


def menu(manager, user=None):
    if user is not None:
        return subscription_menu(manager, user)
    while True:
        try:
            options = []
            for slot in range(1, 9):
                if (manager.directory(slot) / "endpoint.json").exists():
                    value = manager.load(slot)
                    options.append((value["name"] + " / " + value["mode"], str(slot)))
            options.extend([("Создать подключение Snell v6", "create"), ("Добавить внешнюю ссылку в подписку", "import")])
            action = choose("Snell v6 — настройки сохранены отдельно от Snell v5", options)
            if action is None:
                return
            if action == "import":
                database = database_path()
                selected = select_user(database, user)
                if selected:
                    link = input("Ссылка Snell v6 (Enter — отмена): ").strip()
                    if link:
                        print("Ссылка добавлена." if import_link(database, selected, link) else "Эта ссылка уже есть.")
            elif action == "create":
                slot = next((str(i) for i in range(1, 9) if not (manager.directory(i) / "endpoint.json").exists()), None)
                if slot is None:
                    raise Error("Все восемь сохранённых подключений заняты")
                host = input("IP/домен сервера (Enter — отмена): ").strip()
                if not host:
                    continue
                name = input("Имя [Snell-v6]: ").strip() or "Snell-v6"
                changes = {"server_host": host, "name": name}
                if confirm("Создать Snell v6: свободный порт, mode=default, маршрут Xray? Активация выполняется отдельно."):
                    print(json.dumps(manager.apply(slot, changes, create=True, db_path=database_path(), prepare_only=True), ensure_ascii=False))
                    endpoint_menu(manager, slot, user)
            else:
                endpoint_menu(manager, action, user)
        except (Error, ValueError, OSError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
            print("Snell v6: " + (str(error) if isinstance(error, (Error, ValueError)) else type(error).__name__))
        except (EOFError, KeyboardInterrupt):
            print("\nМеню закрыто.")
            return


def state_label(state):
    return {"active": "РАБОТАЕТ", "inactive": "ОСТАНОВЛЕН", "failed": "ОШИБКА",
            "activating": "ЗАПУСКАЕТСЯ", "deactivating": "ОСТАНАВЛИВАЕТСЯ",
            "reloading": "ПЕРЕЗАГРУЖАЕТ НАСТРОЙКИ"}.get(state, "СТАТУС НЕИЗВЕСТЕН")

def status_summary(rows):
    if not rows:
        return "НЕ НАСТРОЕН"
    states = [row.get("ActiveState") for row in rows]
    if states.count("active") > 1:
        return "ОШИБКА: одновременно работают несколько подключений"
    for state in ("active", "failed", "activating", "deactivating", "reloading"):
        if state in states:
            return state_label(state)
    return "ОСТАНОВЛЕН" if all(state == "inactive" for state in states) else "СТАТУС НЕИЗВЕСТЕН"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "set", "update", "publish", "uri", "status", "menu", "firewall"))
    parser.add_argument("--slot", choices=[str(i) for i in range(1, 9)], default="1")
    parser.add_argument("--core-source", type=Path, help="Local binary, still checked against the fixed release SHA-256")
    parser.add_argument("--user")
    parser.add_argument("--human", action="store_true", help="Readable status summary")
    args = parser.parse_args()
    if args.human and args.action != "status":
        parser.error("--human is only supported for status")
    if os.geteuid() != 0:
        raise Error("Run as root")
    if args.action not in ("uri", "status"):
        os_release = Path("/etc/os-release").read_text()
        if (not re.search(r'(?m)^ID=debian$', os_release)
                or not re.search(r'(?m)^VERSION_ID="?(12|13)"?$', os_release)
                or platform.machine() not in ("x86_64", "amd64")):
            raise Error("Snell6 requires Debian 12/13 amd64")
    os.umask(0o077)
    manager = Manager()
    if args.action == "menu":
        menu(manager, args.user)
        return
    if args.action == "firewall":
        manager.ensure_firewall(args.slot)
        return
    if args.action == "status":
        rows = []
        for slot in range(1, 9):
            if (manager.directory(slot) / "endpoint.json").exists():
                value = manager.load(slot)
                rows.append({k: v for k, v in value.items() if k not in ("psk", "probe_url")}
                            | manager.state(slot))
        if args.human:
            print(status_summary(rows))
            return
        result = rows
    elif args.action == "uri":
        value = manager.load(args.slot)
        print(load_helper("snell-subscriptions").uri(value, value["server_host"]))
        return
    elif args.action == "publish":
        database = database_path()
        if not args.user or database is None:
            raise Error("Publish requires explicit --user and an installed TUNA database")
        result = manager.publish(args.slot, args.user, database)
    else:
        changes = json.load(sys.stdin) if args.action in ("create", "set") else {}
        result = manager.apply(args.slot, changes, create=args.action == "create",
                               source=args.core_source, db_path=database_path(), prepare_only=args.action == "create")
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Snell6 failed: " + (str(error) if isinstance(error, Error) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
