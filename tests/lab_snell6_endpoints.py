#!/usr/bin/env python3
"""Production endpoint manager against real core/systemd/HTTPS and local Xray.

Disposable nspawn only. Requires the already pinned Snell core and the previously
qualified Xray copied to /opt/xm-snell6-qa-xray. No VPS or external requests.
"""
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time

from lab_snell_switch import snapshot, restore

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("snell6_qa", ROOT / "scripts/snell6-endpoints.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
SLOT = "8"
UNIT = "snell6@8.service"
SOURCE = Path("/opt/snell6-qualification-20261005/sing-box")
XRAY = Path("/opt/xm-snell6-qa-xray")
TEMPLATE = Path("/etc/systemd/system/snell6@.service")
XRAY_HASH = "c4ae6798c38e0e5343b192406746333cd0ba7ff3eb984f8c4b9939dcb68c3f8a"


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=20)


def main():
    assert Path("/.x-manager-test-lab").is_file()
    assert Path("/run/systemd/container").read_text().strip() == "systemd-nspawn"
    assert module.digest(SOURCE) == module.CORE_SHA256
    assert module.digest(XRAY) == XRAY_HASH
    manager = module.Manager()
    assert not manager.directory(SLOT).exists(), "existing endpoint must not be replaced"
    assert not TEMPLATE.exists(), "existing template must not be replaced"
    guard = manager.lifecycle().dropin(UNIT)
    assert not guard.exists()
    switch = module.load_helper("snell-switch")
    controller = switch.Controller()
    lifecycle = controller.lifecycle
    before_units = {unit: lifecycle.status(unit) for unit in switch.UNITS}
    assert all(state["ActiveState"] == "inactive" for unit, state in before_units.items()
               if unit != "snell.service"), "another lab Snell endpoint is running"
    paths = [TEMPLATE, lifecycle.state_path, Path(switch.SELECTION)]
    for unit in switch.UNITS:
        paths.extend((*lifecycle.markers(unit), lifecycle.dropin(unit)))
    files = snapshot(paths)
    backup = Path(tempfile.mkdtemp(prefix="snell6-endpoint-before-", dir="/var/backups"))
    backup.chmod(0o700)
    (backup / "snapshot.json").write_text(json.dumps({"files": files, "units": before_units}, indent=2))
    (backup / "snapshot.json").chmod(0o600)
    v5 = {str(p): module.digest(p) for p in Path("/etc/snell").glob("*") if p.is_file()}
    os.umask(0o077)
    rows = []
    with tempfile.TemporaryDirectory(prefix="snell6-endpoint-qa-") as temporary:
        work = Path(temporary)
        certificate, key = work / "certificate.pem", work / "key.pem"
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(certificate))
        os.environ["SSL_CERT_FILE"] = str(certificate)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"synthetic-snell6-acceptance")

            def log_message(self, *args):
                pass

        https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        thread = threading.Thread(target=https.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            socks_port = reserve.getsockname()[1]
        xray_config = work / "xray.json"
        xray_config.write_text(json.dumps({"log": {"loglevel": "error"}, "inbounds": [
            {"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [{"protocol": "freedom"}]}))
        xray = subprocess.Popen([str(XRAY), "run", "-c", str(xray_config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for attempt in range(30):
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=.2):
                    break
            except OSError:
                time.sleep(.1)
        database = work / "subscriptions.db"
        db = sqlite3.connect(database)
        db.execute("CREATE TABLE users(id TEXT PRIMARY KEY,snell_uri TEXT,revision INTEGER,updated_at TEXT,subscription_token TEXT)")
        original = "snell://synthetic-v5@192.0.2.1:1488/?version=5#Old"
        db.execute("INSERT INTO users VALUES(?,?,?,?,?)", ("fixture", original, 1, "old", "unchanged-token"))
        db.commit()
        # Same template and privilege prefix; checkout path avoids replacing the
        # lab's installed helpers just to exercise the new version.
        TEMPLATE.write_text((ROOT / "systemd/snell6@.service").read_text().replace(
            "/usr/local/share/x-manager/scripts/snell6-endpoints.py", str(ROOT / "scripts/snell6-endpoints.py")))
        TEMPLATE.chmod(0o644)
        command("systemctl", "daemon-reload")
        try:
            result = manager.apply(SLOT, {"server_host": "192.0.2.1", "listen": "127.0.0.1", "socks_port": socks_port,
                                         "probe_url": "https://localhost:%d/" % https.server_port}, create=True,
                                   source=SOURCE, db_path=database, prepare_only=True)
            assert not result["running_checked"]
            assert controller.switch(6, SLOT)["verification"] == "authenticated"
            assert lifecycle.status("snell.service")["ActiveState"] == "inactive"
            record(rows, "prepared-create-exclusive-switch-nonroot-real-snell-https-through-xray")
            endpoint = manager.load(SLOT)
            pid = command("systemctl", "show", UNIT, "--property=MainPID", "--value").stdout.strip()
            assert Path("/proc", pid).stat().st_uid != 0
            before = {name: module.digest(manager.directory(SLOT) / name) for name in ("endpoint.json", "config.json")}
            assert not manager.apply(SLOT, source=SOURCE, db_path=database)["changed"]
            assert command("systemctl", "show", UNIT, "--property=MainPID", "--value").stdout.strip() == pid
            record(rows, "repeat-keeps-identity-config-and-pid")
            assert manager.publish(SLOT, "fixture", database)["changed"]
            assert not manager.publish(SLOT, "fixture", database)["changed"]
            user = db.execute("SELECT * FROM users").fetchone()
            assert user[1].splitlines()[0] == original and len(user[1].splitlines()) == 2
            assert user[4] == "unchanged-token"
            record(rows, "additive-publish-preserves-v5-token-repeat-idempotent")
            manager.apply(SLOT, {"name": "Renamed v6"}, source=SOURCE, db_path=database)
            assert manager.load(SLOT)["endpoint_id"] == endpoint["endpoint_id"]
            assert db.execute("SELECT snell_uri FROM users").fetchone()[0].endswith("#Renamed%20v6")
            record(rows, "update-keeps-stable-id-and-synchronizes-bound-uri")
            good_files = {name: module.digest(manager.directory(SLOT) / name) for name in ("endpoint.json", "config.json")}
            good_user = db.execute("SELECT * FROM users").fetchone()
            normal_probe = manager.probe

            def fail_once(value, core, runner):
                manager.probe = normal_probe
                raise module.Error("Injected post-start failure")

            manager.probe = fail_once
            try:
                manager.apply(SLOT, {"name": "Rejected change"}, source=SOURCE, db_path=database)
                raise AssertionError("failure injection was hidden")
            except module.Error as error:
                assert "previous state restored" in str(error)
            assert {name: module.digest(manager.directory(SLOT) / name) for name in good_files} == good_files
            assert db.execute("SELECT * FROM users").fetchone() == good_user
            assert manager.state(SLOT)["ActiveState"] == "active"
            record(rows, "post-start-failure-restores-own-files-live-service-and-sqlite")
            manager.lifecycle().change("stop", UNIT)
            result = manager.apply(SLOT, {"name": "Stopped endpoint rename"}, source=SOURCE, db_path=database)
            assert not result["running_checked"] and manager.state(SLOT)["ActiveState"] == "inactive"
            record(rows, "update-respects-manual-stop-inhibit")
            manager.lifecycle().change("start", UNIT)
            xray.terminate()
            xray.wait(timeout=5)
            try:
                manager.publish(SLOT, "fixture", database)
                raise AssertionError("missing Xray silently fell back")
            except (module.Error, OSError):
                pass
            record(rows, "unavailable-xray-blocks-readiness-no-direct-fallback")
            assert {str(p): module.digest(p) for p in Path("/etc/snell").glob("*") if p.is_file()} == v5
            record(rows, "all-v5-files-preserved")
        finally:
            for unit in switch.UNITS:
                command("systemctl", "stop", unit, check=False)
                command("systemctl", "disable", unit, check=False)
            if (manager.directory(SLOT) / "endpoint.json").exists():
                manager.firewall(manager.load(SLOT), False)
            for name in module.FILES:
                (manager.directory(SLOT) / name).unlink(missing_ok=True)
            if manager.directory(SLOT).exists():
                manager.directory(SLOT).rmdir()
            restore(files)
            command("systemctl", "daemon-reload")
            for unit, state in before_units.items():
                if state["UnitFileState"] == "enabled":
                    command("systemctl", "enable", unit)
                elif state["UnitFileState"] == "enabled-runtime":
                    command("systemctl", "enable", "--runtime", unit)
                if state["ActiveState"] == "active":
                    command("systemctl", "start", unit)
            if xray.poll() is None:
                xray.terminate()
                xray.wait(timeout=5)
            https.shutdown()
            https.server_close()
            db.close()
            assert snapshot(paths) == files, "lab lifecycle or selection marker was not restored"
            for unit, state in before_units.items():
                current = lifecycle.status(unit)
                assert current["ActiveState"] == state["ActiveState"], (unit, "running state not restored")
                assert current["UnitFileState"] == state["UnitFileState"], (unit, "autostart state not restored")
            assert {str(p): module.digest(p) for p in Path("/etc/snell").glob("*") if p.is_file()} == v5
            print("RESTORED existing lab Snell files, lifecycle, selection and runtime state", flush=True)
    summary = {"passed": len(rows) == 8, "cases": rows, "core_sha256": module.CORE_SHA256,
               "os": Path("/etc/os-release").read_text(), "prior_lab_restored": True,
               "private_backup": str(backup)}
    Path("/var/tmp/snell6-endpoint-qa-results.json").write_text(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


def record(rows, name):
    rows.append({"case": name, "passed": True})
    print("PASS " + name, flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
