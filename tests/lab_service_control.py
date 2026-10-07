#!/usr/bin/env python3
"""Disposable Debian nspawn only: real systemd lifecycle, activation and reboot.

Run `prepare`, reboot the container, then `after-reboot`. All fixtures have a
dedicated name; existing X-Manager services, state and subscribers are untouched.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location("lifecycle_qa", Path(__file__).resolve().parents[1] / "scripts/service-control.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
PREFIX = "xm-lifecycle-qa"
UNIT = PREFIX + ".service"
STOPPED = PREFIX + "-stopped.service"
DEPENDENT = PREFIX + "-dependent.service"
TIMER = PREFIX + ".timer"
SOCKET = PREFIX + ".socket"
module.UNITS = (UNIT, STOPPED, DEPENDENT, TIMER)
module.STATE_DIR = "/etc/x-manager/lifecycle-qa"
module.RUNTIME_DIR = "/run/x-manager/lifecycle-qa"
controller = module.Controller()
DIRECTORY = Path("/etc/systemd/system")
RESULT = Path("/var/tmp/xm-lifecycle-qa-results.json")
SOCKET_PATH = "/run/xm-lifecycle-qa.sock"


def ctl(*args, check=True):
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=check, timeout=20)


def record(rows, name):
    rows.append({"case": name, "passed": True})
    RESULT.write_text(json.dumps({"os": Path("/etc/os-release").read_text(), "cases": rows}, indent=2))
    print("PASS " + name, flush=True)


def prepare():
    for name in module.UNITS + (SOCKET,):
        assert not (DIRECTORY / name).exists(), "refusing to overwrite fixture " + name
        assert not (DIRECTORY / (name + ".d")).exists()
    assert not Path(module.STATE_DIR).exists(), "previous test state still exists"
    service = "[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\nRestart=always\nRestartSec=100ms\n[Install]\nWantedBy=multi-user.target\n"
    for name in (UNIT, STOPPED):
        (DIRECTORY / name).write_text(service)
    (DIRECTORY / DEPENDENT).write_text("[Unit]\nWants=" + UNIT + "\nAfter=" + UNIT + "\n" + service)
    (DIRECTORY / TIMER).write_text("[Unit]\nDescription=Lifecycle QA timer\n[Timer]\nOnActiveSec=200ms\nAccuracySec=10ms\nUnit=" + UNIT + "\n[Install]\nWantedBy=timers.target\n")
    (DIRECTORY / SOCKET).write_text("[Unit]\nDescription=Lifecycle QA socket\n[Socket]\nListenStream=" + SOCKET_PATH + "\nService=" + UNIT + "\n")
    ctl("daemon-reload")
    rows = []
    controller.change("on", UNIT)
    original = (DIRECTORY / UNIT).read_bytes()
    controller.change("off", UNIT)
    assert (DIRECTORY / UNIT).read_bytes() == original
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    assert controller.status(UNIT)["Restart"] == "no"
    record(rows, "permanent-off-keeps-local-unit-and-disables-restart")

    # This is the exact reactivation mechanism in audited external pollers.
    for operation in ("start", "restart", "reset-failed", "start"):
        ctl(operation, UNIT, check=operation != "reset-failed")
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    record(rows, "external-systemctl-start-restart-cannot-revive-off")

    ctl("start", DEPENDENT)
    assert controller.status(DEPENDENT)["ActiveState"] == "active"
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    ctl("stop", DEPENDENT)
    record(rows, "dependency-activation-cannot-revive-off")

    ctl("start", TIMER)
    time.sleep(.7)
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    ctl("stop", TIMER)
    record(rows, "timer-activation-cannot-revive-off")

    ctl("start", SOCKET)
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(.5)
        client.connect(SOCKET_PATH)
    time.sleep(.3)
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    ctl("stop", SOCKET)
    record(rows, "socket-activation-cannot-revive-off")

    try:
        controller.change("start", UNIT)
        raise AssertionError("persistent off accepted normal start")
    except ValueError:
        pass
    controller.change("on", UNIT)
    assert controller.status(UNIT)["ActiveState"] == "active"
    assert controller.status(UNIT)["Restart"] == "always"
    record(rows, "explicit-on-restores-original-restart-policy")

    controller.change("stop", UNIT)
    for operation in ("start", "restart"):
        ctl(operation, UNIT)
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    assert controller.status(UNIT)["UnitFileState"] == "enabled"
    controller.change("start", UNIT)
    record(rows, "manual-stop-inhibits-pollers-until-explicit-start")

    controller.change("autostart-off", UNIT)
    assert controller.status(UNIT)["ActiveState"] == "active"
    controller.change("stop", UNIT)
    controller.change("start", UNIT)
    assert controller.status(UNIT)["UnitFileState"] == "disabled"
    record(rows, "autostart-off-keeps-running-and-allows-manual-start")

    controller.change("off", UNIT)
    # Simulate installer replacing the local service while leaving owned state.
    (DIRECTORY / UNIT).write_text(service + "# new package version\n")
    controller.reconcile()
    ctl("restart", UNIT)
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    record(rows, "package-unit-replacement-reconcile-retains-off")

    conflict = DIRECTORY / (UNIT + ".d") / "99-qa-conflict.conf"
    conflict.write_text("[Unit]\nConditionPathExists=\n")
    ctl("daemon-reload")
    try:
        controller.change("on", UNIT)
        raise AssertionError("effective condition reset was missed")
    except ValueError as error:
        assert "removed lifecycle guard" in str(error)
    finally:
        conflict.unlink()
        ctl("daemon-reload")
    assert controller.status(UNIT)["off"]
    record(rows, "effective-competing-condition-reset-reported")

    controller.change("on", STOPPED)
    controller.change("stop", STOPPED)
    controller.change("off", UNIT)
    # Deliberately add a boot Wants symlink, as a foreign updater might do.
    ctl("enable", UNIT)
    record(rows, "prepared-real-reboot-with-enabled-off-and-runtime-stopped-units")


def after_reboot():
    rows = json.loads(RESULT.read_text())["cases"]
    assert controller.status(UNIT)["off"]
    assert controller.status(UNIT)["ActiveState"] == "inactive"
    assert controller.status(STOPPED)["ActiveState"] == "active"
    assert not controller.status(STOPPED)["stopped"]
    record(rows, "real-reboot-keeps-permanent-off-clears-runtime-stop")
    controller.reconcile()
    assert controller.status(UNIT)["UnitFileState"] == "disabled"
    record(rows, "post-reboot-reconcile-restores-disabled-autostart")
    cleanup()


def cleanup():
    for name in (SOCKET, TIMER, DEPENDENT, UNIT, STOPPED):
        ctl("stop", name, check=False)
        ctl("disable", name, check=False)
        ctl("reset-failed", name, check=False)
        (DIRECTORY / name).unlink(missing_ok=True)
        own_dropin = DIRECTORY / (name + ".d") / module.DROPIN
        own_dropin.unlink(missing_ok=True)
        if own_dropin.parent.exists():
            own_dropin.parent.rmdir()
    for name in (module.STATE_DIR, module.RUNTIME_DIR):
        location = Path(name)
        assert location.name == "lifecycle-qa" and location.parent.name == "x-manager"
        if location.exists():
            shutil.rmtree(location)
    Path(SOCKET_PATH).unlink(missing_ok=True)
    ctl("daemon-reload")


if __name__ == "__main__":
    assert Path("/.x-manager-test-lab").is_file(), "requires disposable lab marker"
    assert Path("/run/systemd/container").read_text().strip() == "systemd-nspawn"
    assert 'ID=debian' in Path("/etc/os-release").read_text()
    {"prepare": prepare, "after-reboot": after_reboot, "cleanup": cleanup}[sys.argv[1]]()
