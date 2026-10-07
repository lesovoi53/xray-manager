#!/usr/bin/env python3
"""Native v5/v6 switching in the marked Debian nspawn lab, with full restoration.

Only loopback HTTPS and synthetic PSKs are used. Existing v5 configuration, unit,
lifecycle state, enabled state and running state are snapshotted and restored.
"""
import base64
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=30)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def snapshot(paths):
    result = {}
    for path in paths:
        if path.is_symlink():
            result[str(path)] = {"link": os.readlink(path)}
        elif path.exists():
            stat = path.stat()
            result[str(path)] = dict(data=base64.b64encode(path.read_bytes()).decode(),
                                     mode=stat.st_mode & 0o777, uid=stat.st_uid, gid=stat.st_gid)
        else:
            result[str(path)] = None
    return result


def restore(files):
    for name, entry in files.items():
        path = Path(name)
        if path.exists() or path.is_symlink():
            path.unlink()
        if entry is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            if "link" in entry:
                path.symlink_to(entry["link"])
            else:
                path.write_bytes(base64.b64decode(entry["data"]))
                path.chmod(entry["mode"])
                os.chown(path, entry["uid"], entry["gid"])


def main():
    assert Path("/.x-manager-test-lab").is_file()
    assert Path("/run/systemd/container").read_text().strip() == "systemd-nspawn"
    assert 'VERSION_ID="13"' in Path("/etc/os-release").read_text()
    switch, endpoints = load("snell-switch"), load("snell6-endpoints")
    manager = endpoints.Manager()
    controller = switch.Controller()
    unit, slot = "snell6@8.service", "8"
    template = Path("/etc/systemd/system/snell6@.service")
    v5unit = Path("/etc/systemd/system/snell.service")
    v5config = Path("/etc/snell/snell-server.conf")
    source = Path("/opt/snell6-qualification-20261005/sing-box")
    assert endpoints.digest(source) == endpoints.CORE_SHA256
    assert not template.exists(), "refuse to replace another lab's template"
    assert not manager.directory(slot).exists(), "refuse to replace another lab's endpoint"
    assert not any(s["conflict"] for s in controller.lifecycle.conflicts())
    lifecycle = controller.lifecycle
    before_units = {u: lifecycle.status(u) for u in switch.UNITS}
    assert all(s["ActiveState"] == "inactive" for u, s in before_units.items() if u != "snell.service")
    paths = [v5unit, v5config, template, lifecycle.state_path, Path(switch.SELECTION)]
    for u in switch.UNITS:
        paths.extend((*lifecycle.markers(u), lifecycle.dropin(u)))
    files = snapshot(paths)
    backup = Path(tempfile.mkdtemp(prefix="snell-switch-lab-before-", dir="/var/backups"))
    backup.chmod(0o700)
    (backup / "snapshot.json").write_text(json.dumps({"files": files, "units": before_units}, indent=2))
    (backup / "snapshot.json").chmod(0o600)
    rows, overlaps, samples = [], [], []
    monitor_stop = threading.Event()
    os.umask(0o077)
    v5port = port()
    v6port = port()
    assert v5port != v6port
    def record(name):
        rows.append({"case": name, "passed": True})
        print("PASS " + name, flush=True)
    with tempfile.TemporaryDirectory(prefix="snell-switch-https-") as temporary:
        work = Path(temporary)
        cert, key = work / "cert.pem", work / "key.pem"
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout", str(key), "-out", str(cert))
        os.environ["SSL_CERT_FILE"] = str(cert)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"synthetic-switch-acceptance")
            def log_message(self, *args):
                pass
        https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        threading.Thread(target=https.serve_forever, daemon=True).start()
        probe_url = "https://127.0.0.1:%d/" % https.server_port
        def probe(value, core, runner):
            assert core is not None
            with switch.deadline(30):
                endpoints.endpoint_probe(dict(value, probe_url=probe_url), core, runner)
        controller.probe = probe
        def monitor():
            while not monitor_stop.is_set():
                listeners = {int(line.split()[1].rsplit(":", 1)[1], 16)
                             for line in Path("/proc/net/tcp").read_text().splitlines()[1:]
                             if line.split()[3] == "0A"}
                samples.append(1)
                if {v5port, v6port} <= listeners:
                    overlaps.append(True)
                monitor_stop.wait(.02)
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        try:
            command("systemctl", "stop", "snell.service")
            # Synthetic native-v5 fixture skips the existing machine's routing
            # hook, so test traffic cannot leave loopback through its gateways.
            text = (ROOT / "systemd/snell.service").read_text()
            text = "\n".join(line for line in text.splitlines() if not line.startswith("ExecStartPre=")) + "\n"
            v5unit.write_text(text)
            v5unit.chmod(0o644)
            v5config.write_text("[snell-server]\nlisten = 127.0.0.1:%d\npsk = synthetic-switch-v5-key\n" % v5port)
            v5config.chmod(0o640)
            os.chown(v5config, 0, pwd.getpwnam("snell").pw_gid)
            template.write_text((ROOT / "systemd/snell6@.service").read_text().replace(
                "/usr/local/share/x-manager/scripts/snell6-endpoints.py", str(ROOT / "scripts/snell6-endpoints.py")))
            template.chmod(0o644)
            command("systemctl", "daemon-reload")
            manager.apply(slot, {"server_host": "127.0.0.1", "listen": "127.0.0.1", "routing": "direct",
                                 "port": v6port, "probe_url": probe_url}, create=True, source=source, prepare_only=True)
            config_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in (v5config, manager.directory(slot) / "endpoint.json", manager.directory(slot) / "config.json")}
            monitor_thread.start()
            assert controller.switch(5)["verification"] == "authenticated"
            record("native-v5-authenticated-v4-client-loopback-https")
            value = manager.load(slot)
            manager.firewall(value, False)
            assert not manager.firewall_exists(value)
            assert controller.switch(6, slot)["verification"] == "authenticated"
            assert manager.firewall_exists(value)
            assert lifecycle.status("snell.service")["off"]
            assert lifecycle.status("snell.service")["UnitFileState"] == "disabled"
            record("v5-to-v6-authenticated-https-restores-owned-firewall")
            old_pid = command("systemctl", "show", unit, "--property=MainPID", "--value").stdout.strip()
            assert not controller.switch(6, slot)["changed"]
            assert command("systemctl", "show", unit, "--property=MainPID", "--value").stdout.strip() == old_pid
            record("repeat-keeps-selected-process-and-configuration")
            lifecycle.reconcile()
            command("systemctl", "start", "snell.service")
            assert lifecycle.status("snell.service")["ActiveState"] == "inactive"
            assert lifecycle.status(unit)["ActiveState"] == "active"
            record("disabled-version-retains-boot-inhibit-and-rejects-external-start")
            assert controller.switch(5)["verification"] == "authenticated"
            assert lifecycle.status(unit)["off"] and lifecycle.status(unit)["UnitFileState"] == "disabled"
            record("v6-to-v5-authenticated-v4-client-restores-exclusive-version")
            before_failure = snapshot([lifecycle.state_path, Path(switch.SELECTION)] +
                                      [p for u in switch.UNITS for p in (*lifecycle.markers(u), lifecycle.dropin(u))])
            before_live = {u: lifecycle.status(u) for u in switch.UNITS}
            manager.firewall(value, False)
            def failed_probe(value, core, runner):
                raise RuntimeError("injected post-start readiness failure")
            controller.probe = failed_probe
            try:
                controller.switch(6, slot)
                raise AssertionError("injected failure was ignored")
            except RuntimeError as error:
                assert "previous lifecycle state restored" in str(error)
            assert snapshot([Path(p) for p in before_failure]) == before_failure
            assert not manager.firewall_exists(value)
            for u, state in before_live.items():
                now = lifecycle.status(u)
                assert all(now[k] == state[k] for k in ("ActiveState", "UnitFileState", "off", "stopped", "autostart")), (u, now, state)
            controller.probe = probe
            assert not controller.switch(5)["changed"]
            record("post-start-failure-restores-v5-intent-marker-autostart-and-firewall")
            assert {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in config_hashes} == config_hashes
            record("all-v5-and-v6-configurations-and-identities-preserved")
            for obfs in ("http", "tls"):
                controller.switch(6, slot)
                synthetic = ("[snell-server]\nlisten = 127.0.0.1:%d\npsk = synthetic-switch-v5-key\n"
                             "obfs = %s\nobfs-host = cover.example\n") % (v5port, obfs)
                v5config.write_text(synthetic)
                if obfs == "http":
                    assert controller.switch(5)["verification"] == "authenticated"
                    assert v5config.read_text() == synthetic
                    record("native-v5-http-obfs-authenticated-v4-client-preserves-configuration")
                else:
                    # Official native v4/v5 supports HTTP only. The pinned
                    # extended client supports TLS for compatible backends;
                    # incompatible native server must fail without rewriting it.
                    # https://manual.nssurge.com/policies/snell.html
                    try:
                        controller.switch(5)
                        raise AssertionError("unsupported native TLS-obfs reported success")
                    except RuntimeError as error:
                        assert "previous lifecycle state restored" in str(error)
                    assert v5config.read_text() == synthetic
                    assert switch.read_selection()["version"] == 6
                    assert lifecycle.status(unit)["ActiveState"] == "active"
                    assert lifecycle.status("snell.service")["ActiveState"] == "inactive"
                    record("unsupported-native-v5-tls-obfs-fails-and-restores-selected-v6-with-config-preserved")
            assert samples and not overlaps
            record("no-simultaneous-native-listeners-during-all-switches")
        finally:
            monitor_stop.set()
            if monitor_thread.is_alive():
                monitor_thread.join(timeout=2)
            for u in switch.UNITS:
                command("systemctl", "stop", u, check=False)
                command("systemctl", "disable", u, check=False)
            if (manager.directory(slot) / "endpoint.json").exists():
                manager.firewall(manager.load(slot), False)
            for name in endpoints.FILES:
                (manager.directory(slot) / name).unlink(missing_ok=True)
            if manager.directory(slot).exists():
                manager.directory(slot).rmdir()
            restore(files)
            command("systemctl", "daemon-reload")
            for u, state in before_units.items():
                if state["UnitFileState"] == "enabled":
                    command("systemctl", "enable", u)
                elif state["UnitFileState"] == "enabled-runtime":
                    command("systemctl", "enable", "--runtime", u)
                if state["ActiveState"] == "active":
                    command("systemctl", "start", u)
            https.shutdown()
            https.server_close()
            assert snapshot(paths) == files, "lab files were not restored"
            assert lifecycle.status("snell.service")["ActiveState"] == before_units["snell.service"]["ActiveState"]
            assert lifecycle.status("snell.service")["UnitFileState"] == before_units["snell.service"]["UnitFileState"]
            print("RESTORED existing lab Snell files, lifecycle and runtime state", flush=True)
    report = dict(passed=len(rows) == 10, cases=rows, listener_samples=len(samples),
                  simultaneous_listener_samples=len(overlaps), prior_lab_restored=True,
                  private_backup=str(backup), core_sha256=endpoints.CORE_SHA256,
                  native_v5_sha256=endpoints.digest(Path("/usr/local/bin/snell-server")))
    Path("/var/tmp/snell-switch-qa-results.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
