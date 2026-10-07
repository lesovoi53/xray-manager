"""Disposable Debian 12/13 nspawn only; owns two temporary fixture units."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[1]


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15)


def ctl(*args, check=True):
    return command("systemctl", *args, check=check)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert Path("/.x-manager-test-lab").is_file(), "disposable lab marker required"
    assert Path("/run/systemd/container").read_text().strip() == "systemd-nspawn"
    spec = importlib.util.spec_from_file_location("lab_health", SOURCE / "scripts/watchdog-health.py")
    health = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(health)
    Path("/etc/x-manager").mkdir(exist_ok=True)
    qa = Path(tempfile.mkdtemp(prefix="qa-health-", dir="/etc/x-manager"))
    fixture = "xm-" + qa.name + ".service"
    poller = "xm-" + qa.name + "-poller.service"
    units = [Path("/etc/systemd/system") / u for u in (fixture, poller)]
    assert all(not p.exists() and not p.is_symlink() for p in units)
    runtime = Path("/run/x-manager") / qa.name
    health.CONFIG, health.STATE, health.HEALTH_LOCK = str(qa / "config.json"), str(qa / "state.json"), str(qa / "lock")
    health.UNITS = (fixture,)
    health.control.UNITS = (fixture, poller)
    health.control.EXTERNAL_WATCHDOGS = (poller,)
    health.control.STATE_DIR = str(qa / "lifecycle")
    health.control.RUNTIME_DIR = str(runtime)
    clock = [1000]
    engine = health.Health(now=lambda: clock[0])
    rows = []
    started = time.monotonic()
    failure = None

    def passed(case, predicate=True):
        assert predicate, case
        rows.append({"case": case, "passed": True})

    def pid():
        return int(engine.show(fixture).get("MainPID", "0"))

    def outcome():
        return engine.check()["units"][0]

    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
    setting = dict(kind="http", host="127.0.0.1", port=port, path="/health",
                   failures=2, cooldown=30, max_restarts=2, timeout=1)
    healthy = qa / "healthy"
    healthy.touch()
    fixture_script = qa / "fixture.py"
    fixture_script.write_text('''import http.server, pathlib, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204 if pathlib.Path(__file__).with_name("healthy").exists() else 503)
        self.end_headers()
    def log_message(self, *args): pass
class Server(http.server.HTTPServer): allow_reuse_address = True
Server(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
''')
    units[0].write_text(f"[Unit]\nDescription=Disposable health-check fixture\n[Service]\nType=simple\nExecStart=/usr/bin/python3 {fixture_script} {port}\nRestart=no\n[Install]\nWantedBy=multi-user.target\n")
    units[1].write_text("[Unit]\nDescription=Disposable health owner fixture\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\nRestart=no\n")
    for path in units:
        path.chmod(0o644)

    def ready():
        end = time.monotonic() + 5
        while time.monotonic() < end:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return
            except OSError:
                time.sleep(.03)
        raise AssertionError("fixture listener not ready")

    try:
        ctl("daemon-reload")
        ctl("start", fixture)
        ready()
        timer_before = ctl("show", "tuna-healthcheck.timer", "--property=UnitFileState,ActiveState").stdout
        engine.configure("set", fixture, setting)
        passed("set-does-not-enable-timer", timer_before == ctl("show", "tuna-healthcheck.timer", "--property=UnitFileState,ActiveState").stdout)
        first = pid()
        passed("healthy-http-keeps-running-pid", outcome()["status"] == "healthy" and pid() == first)
        healthy.unlink()
        passed("first-real-http-failure-only-counts", outcome()["status"] == "unhealthy" and pid() == first)
        passed("second-failure-restarts-own-fixture", outcome()["status"] == "restarted" and pid() != first)
        ready()
        second = pid()
        outcome()
        passed("cooldown-keeps-new-pid", outcome()["status"] == "cooldown" and pid() == second)
        clock[0] += 31
        passed("second-allowed-restart", outcome()["status"] == "restarted" and pid() != second)
        ready()
        third = pid()
        outcome()
        clock[0] += 31
        passed("exhausted-budget-stops-restarts", outcome()["status"] == "exhausted" and pid() == third)
        healthy.touch()
        passed("healthy-does-not-refill-budget", outcome()["attempts"] == 2)
        engine.configure("remove", fixture)
        engine.configure("set", fixture, setting)
        passed("remove-and-readd-retain-attempts", engine.report()["counters"]["units"][fixture]["attempts"] == 2)
        engine.configure("reset", fixture)
        healthy.unlink()
        outcome()
        passed("explicit-reset-permits-recovery", outcome()["status"] == "restarted")
        ready()
        ctl("stop", fixture)
        passed("manual-systemctl-stop-is-preserved", outcome()["status"] == "skipped" and pid() == 0)
        engine.controller.change("off", fixture)
        ctl("start", fixture)
        passed("persistent-off-blocks-direct-systemd-start", pid() == 0 and outcome()["status"] == "skipped")
        engine.controller.change("on", fixture)
        ready()
        passed("explicit-on-restores-own-fixture", pid() > 0)
        engine.controller.change("stop", fixture)
        passed("manual-lifecycle-stop-is-preserved", outcome()["status"] == "skipped" and pid() == 0)
        engine.controller.change("start", fixture)
        ready()
        ctl("start", poller)
        passed("external-owner-conflict-blocks-check", engine.check()["status"] == "blocked")
        ctl("stop", poller)
        with Path(health.INSTALL_LOCK).open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            passed("installer-lock-skips-check", engine.check()["status"] == "skipped")
        process = dict(setting, kind="process", port=None)
        engine.configure("set", fixture, process)
        passed("real-main-process-check", outcome()["status"] == "healthy")
        before = Path(health.CONFIG).read_bytes()
        try:
            engine.configure("set", fixture, dict(setting, host="192.0.2.1"))
        except ValueError:
            pass
        else:
            raise AssertionError("remote target accepted")
        passed("remote-target-refused-without-config-change", Path(health.CONFIG).read_bytes() == before)
        counters = Path(health.STATE).read_bytes()
        engine.report()
        passed("report-is-read-only", Path(health.STATE).read_bytes() == counters and Path(health.CONFIG).read_bytes() == before)
    except Exception as exc:
        failure = type(exc).__name__ + ": " + str(exc)
    finally:
        cleanup_errors = []
        for unit, path in zip((fixture, poller), units):
            stopped = ctl("stop", unit, check=False)
            if stopped.returncode:
                cleanup_errors.append("stop " + unit)
            ctl("disable", unit, check=False)
            path.unlink(missing_ok=True)
            dropin = path.with_name(path.name + ".d")
            guard = dropin / health.control.DROPIN
            guard.unlink(missing_ok=True)
            if dropin.exists():
                dropin.rmdir()
        ctl("daemon-reload")
        for unit in (fixture, poller):
            ctl("reset-failed", unit, check=False)
            if ctl("show", unit, "--property=MainPID", "--value").stdout.strip() not in ("", "0"):
                cleanup_errors.append("live PID " + unit)
        assert qa.resolve().parent == Path("/etc/x-manager") and qa.name.startswith("qa-health-")
        shutil.rmtree(qa)
        if runtime.exists():
            assert runtime.resolve().parent == Path("/run/x-manager") and runtime.name == qa.name
            shutil.rmtree(runtime)
        if cleanup_errors:
            failure = "; ".join(cleanup_errors)
        rows.append({"case": "fixture-services-and-files-removed", "passed": not cleanup_errors})
    result = {"passed": failure is None and len(rows) == 20 and all(r["passed"] for r in rows),
              "failure": failure, "cases": rows, "seconds": round(time.monotonic() - started, 2),
              "systemd": command("systemctl", "--version").stdout.splitlines()[0],
              "note": "Only two disposable fixture units changed; no package service or external network was used."}
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
