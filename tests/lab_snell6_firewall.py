#!/usr/bin/env python3
"""Disposable systemd boot-hook test. prepare -> reboot -> check -> reboot -> off.

Native config and actual service are used; data-path readiness was tested by
lab_snell6_endpoints.py. This test bypasses that separate HTTPS probe only.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("snell6_fw_qa", ROOT / "scripts/snell6-endpoints.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
manager = module.Manager(probe=lambda *args: None)
SLOT, UNIT = "7", "snell6@7.service"
TEMPLATE = Path("/etc/systemd/system/snell6@.service")
SOURCE = Path("/opt/snell6-qualification-20261005/sing-box")
RESULT = Path("/var/tmp/snell6-firewall-qa.json")
CANARY = ["-p", "tcp", "--dport", "65001", "-m", "comment", "--comment", "XM_SNELL6_QA_FOREIGN", "-j", "DROP"]


def ctl(*args):
    return subprocess.run(["systemctl", *args], check=True, capture_output=True, text=True)


def prepare():
    assert not manager.directory(SLOT).exists() and not TEMPLATE.exists()
    TEMPLATE.write_text((ROOT / "systemd/snell6@.service").read_text().replace(
        "/usr/local/share/x-manager/scripts/snell6-endpoints.py", str(ROOT / "scripts/snell6-endpoints.py")))
    TEMPLATE.chmod(0o644)
    ctl("daemon-reload")
    manager.apply(SLOT, {"server_host": "192.0.2.1", "routing": "direct", "listen": "127.0.0.1"}, create=True, source=SOURCE)
    value = manager.load(SLOT)
    assert manager.firewall_exists(value)
    manager.firewall(value, False)
    RESULT.write_text(json.dumps({"endpoint_id": value["endpoint_id"], "cases": []}))


def check():
    value = manager.load(SLOT)
    assert manager.state(SLOT)["ActiveState"] == "active"
    assert manager.firewall_exists(value), "own rule was not restored at boot"
    record("actual-reboot-restores-only-owned-rule")
    subprocess.run(["iptables", "-w", "-I", "INPUT", *CANARY], check=True)
    try:
        manager.firewall(value, False)
        ctl("restart", UNIT)
        assert manager.firewall_exists(value)
        subprocess.run(["iptables", "-w", "-C", "INPUT", *CANARY], check=True)
        record("privileged-start-hook-keeps-foreign-rule")
        manager.lifecycle().change("off", UNIT)
        manager.firewall(value, False)
        ctl("start", UNIT)
        assert not manager.firewall_exists(value)
        record("persistent-off-skips-privileged-firewall-hook")
    finally:
        subprocess.run(["iptables", "-w", "-D", "INPUT", *CANARY], check=True)


def off():
    value = manager.load(SLOT)
    assert manager.state(SLOT)["ActiveState"] == "inactive"
    assert not manager.firewall_exists(value)
    record("actual-reboot-of-off-endpoint-does-not-open-rule")
    ctl("stop", UNIT)
    ctl("disable", UNIT)
    for filename in module.FILES:
        (manager.directory(SLOT) / filename).unlink(missing_ok=True)
    manager.directory(SLOT).rmdir()
    TEMPLATE.unlink()
    lifecycle = manager.lifecycle()
    guard = lifecycle.dropin(UNIT)
    guard.unlink()
    guard.parent.rmdir()
    for marker in lifecycle.markers(UNIT):
        marker.unlink(missing_ok=True)
    state = lifecycle.read()
    state["units"].pop(UNIT, None)
    if state["units"]:
        lifecycle.save(state)
    else:
        lifecycle.state_path.unlink(missing_ok=True)
    ctl("daemon-reload")


def record(name):
    result = json.loads(RESULT.read_text())
    result["cases"].append({"case": name, "passed": True})
    RESULT.write_text(json.dumps(result, indent=2))
    print("PASS " + name, flush=True)


if __name__ == "__main__":
    assert Path("/.x-manager-test-lab").is_file()
    assert Path("/run/systemd/container").read_text().strip() == "systemd-nspawn"
    {"prepare": prepare, "check": check, "off": off}[sys.argv[1]]()
