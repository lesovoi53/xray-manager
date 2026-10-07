#!/usr/bin/env python3
"""Bounded, read-only Linux resource/network snapshot; no external probes.

Only selected kernel counters, selected systemd properties and sysctl declarations
are collected. Never collect process arguments, environment, configs or journals.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

MAX_BYTES = 262144
SYSCTLS = (
    "net.ipv4.tcp_congestion_control", "net.ipv4.tcp_available_congestion_control",
    "net.core.default_qdisc", "net.core.rmem_max", "net.core.wmem_max",
    "net.core.netdev_max_backlog", "net.core.somaxconn", "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem", "net.ipv4.tcp_max_syn_backlog", "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_keepalive_intvl",
    "net.ipv4.tcp_keepalive_probes", "net.ipv4.ip_forward",
    "net.ipv6.conf.all.forwarding", "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter", "net.netfilter.nf_conntrack_count",
    "net.netfilter.nf_conntrack_max", "net.netfilter.nf_conntrack_tcp_timeout_established",
    "fs.file-max", "fs.nr_open",
)
UNITS = tuple(name + ".service" for name in (
    "x-ui", "snell", "mita", "wdtt", "csqtt", "webdav-tunnel",
    "masterdns", "cottendns", "tuna-subscriptions", "sing-box", "caddy",
    "vpn-watchdog", "tuna-watchdog")) + tuple(
    "openflux@%d.service" % i for i in range(1, 9)) + (
    "vpn-watchdog.timer", "tuna-watchdog.timer")
PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID",
    "Restart", "NRestarts", "LimitNOFILE", "LimitNOFILESoft", "MemoryCurrent",
    "MemoryPeak", "MemoryHigh", "MemoryMax", "TasksCurrent", "TasksMax",
    "StartLimitBurst", "StartLimitIntervalUSec", "FragmentPath", "DropInPaths",
)
KNOWN_WATCHDOG = "34fd858fc459fd206f198f159f0f9b60ce80ff374e847d356f071a433e951825"


def unchecked(reason):
    return {"status": "not_checked", "reason": reason}


def ok(value, source=None):
    result = {"status": "ok", "value": value}
    if source:
        result["source"] = source
    return result


def redact(value):
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value
    value = re.sub(r"(?i)\b[a-z][a-z0-9+.-]*://\S+", "<URL_REDACTED>", value)
    value = re.sub(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", "<UUID_REDACTED>", value)
    return re.sub(r"(?i)\b(password|token|secret|cookie|authorization|psk)\s*[=:]\s*\S+",
                  r"\1=<REDACTED>", value)


class Collector:
    def __init__(self, root="/", timeout=2.0, budget=20.0, runner=None):
        self.root = Path(root)
        self.timeout = timeout
        self.deadline = time.monotonic() + budget
        self.runner = runner or subprocess.run

    def read(self, name):
        if time.monotonic() >= self.deadline:
            return unchecked("total time budget exhausted")
        try:
            with (self.root / name.lstrip("/")).open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                return unchecked("file exceeds bounded read limit")
            return ok(data.decode("utf-8", "replace"), name)
        except FileNotFoundError:
            return unchecked("file unavailable")
        except OSError:
            return unchecked("file inaccessible")

    def command(self, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return unchecked("total time budget exhausted")
        try:
            result = self.runner(args, capture_output=True, text=True,
                                 timeout=min(self.timeout, remaining),
                                 env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
                                      "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"})
        except FileNotFoundError:
            return unchecked("command unavailable: " + args[0])
        except subprocess.TimeoutExpired:
            return unchecked("command timed out: " + args[0])
        except OSError:
            return unchecked("command inaccessible: " + args[0])
        if result.returncode:
            # Never include arbitrary stderr: it may contain config values.
            return unchecked("command failed: %s (exit %d)" % (args[0], result.returncode))
        if len(result.stdout) > MAX_BYTES:
            return unchecked("command output exceeds report limit")
        return ok(result.stdout.strip())

    def numbers(self, name):
        result = self.read(name)
        if result["status"] != "ok":
            return result
        if not re.fullmatch(r"[\d\s]+", result["value"]):
            return unchecked("unexpected numeric format")
        return ok([int(item) for item in result["value"].split()], name)

    def declarations(self):
        """Show declarations, never claim which file produced the live value.

        Runtime writes and differences between sysctl loaders make that unknowable
        from a snapshot. Duplicate basenames/late overrides remain visible.
        """
        records = []
        skipped = []
        paths = [self.root / "etc/sysctl.conf"]
        for directory in ("usr/lib/sysctl.d", "usr/local/lib/sysctl.d", "lib/sysctl.d",
                          "run/sysctl.d", "etc/sysctl.d"):
            try:
                paths.extend(sorted((self.root / directory).glob("*.conf")))
            except OSError:
                skipped.append("/" + directory)
        if len(paths) > 256:
            return unchecked("too many sysctl files for bounded scan")
        for path in paths:
            name = "/" + path.relative_to(self.root).as_posix()
            result = self.read(name)
            if result["status"] != "ok":
                skipped.append(name)
                continue
            for number, line in enumerate(result["value"].splitlines(), 1):
                match = re.match(r"\s*-?([\w./]+)\s*=\s*([^#;]+)", line)
                if match and match[1].replace("/", ".") in SYSCTLS:
                    value = match[2].strip()
                    if re.fullmatch(r"[\w\s.-]{1,256}", value):
                        records.append({"key": match[1].replace("/", "."), "value": value,
                                        "file": name, "line": number})
        return {"status": "ok", "value": records, "not_checked": skipped,
                "note": "Declarations only; runtime source/loader precedence is not inferred."}

    def systemd(self):
        result = self.command("systemctl", "show", "--no-pager",
                              "--property=" + ",".join(PROPERTIES), *UNITS)
        if result["status"] != "ok":
            return result
        units = {}
        for block in result["value"].split("\n\n"):
            fields = dict(line.split("=", 1) for line in block.splitlines()
                          if "=" in line and line.split("=", 1)[0] in PROPERTIES)
            name = fields.get("Id")
            if name not in UNITS:
                continue
            pid = fields.get("MainPID", "0")
            if pid.isdigit() and int(pid) > 0:
                fields["process_nofile"] = self.process_limit(pid)
                try:
                    # Count only entries, never resolve descriptor targets.
                    with os.scandir(self.root / "proc" / pid / "fd") as entries:
                        count = 0
                        for _ in entries:
                            count += 1
                            if count > 65536 or time.monotonic() >= self.deadline:
                                break
                    fields["process_fd_count"] = (ok(count) if count <= 65536 and
                        time.monotonic() < self.deadline else unchecked("descriptor scan limit reached"))
                except OSError:
                    fields["process_fd_count"] = unchecked("process FD directory inaccessible")
            units[name] = fields
        if not units:
            return unchecked("no expected systemd properties returned")
        return ok(units)

    def process_limit(self, pid):
        result = self.read("/proc/%s/limits" % pid)
        if result["status"] != "ok":
            return result
        for line in result["value"].splitlines():
            match = re.fullmatch(r"Max open files\s+(\d+|unlimited)\s+(\d+|unlimited)\s+files\s*", line)
            if match:
                return ok({"soft": match[1], "hard": match[2], "unit": "files"}, result["source"])
        return unchecked("process open-file limit unavailable")

    def collect(self):
        report = {"schema_version": 1, "read_only": True,
                  "scope": "Local snapshot; counters are cumulative, not rates. No reachability/egress proof."}
        release = self.read("/etc/os-release")
        if release["status"] == "ok":
            release["value"] = {key: value.strip('"') for key, value in
                (line.split("=", 1) for line in release["value"].splitlines() if "=" in line)
                if key in ("PRETTY_NAME", "ID", "VERSION_ID")}
        report["os"] = release
        report["kernel"] = self.read("/proc/sys/kernel/osrelease")
        cpu = self.read("/proc/stat")
        if cpu["status"] == "ok":
            cpu["value"] = {"logical_cpus": len(re.findall(r"^cpu\d+\s", cpu["value"], re.M)),
                            "aggregate_ticks": next((line.split()[1:] for line in cpu["value"].splitlines()
                                                     if line.startswith("cpu ")), [])}
        report["cpu"] = cpu
        report["load_average"] = self.read("/proc/loadavg")
        memory = self.read("/proc/meminfo")
        if memory["status"] == "ok":
            memory["value"] = {key: int(value) for key, value in re.findall(
                r"^(MemTotal|MemAvailable|SwapTotal|SwapFree|Slab|SReclaimable):\s+(\d+) kB", memory["value"], re.M)}
            memory["unit"] = "KiB"
        report["memory"] = memory
        report["file_handles"] = self.numbers("/proc/sys/fs/file-nr")
        report["file_handles"]["columns"] = ["allocated", "unused", "maximum"]
        report["effective_sysctl"] = {key: self.read("/proc/sys/" + key.replace(".", "/")) for key in SYSCTLS}
        report["sysctl_declarations"] = self.declarations()
        for name, path in (("tcp_udp_counters", "/proc/net/snmp"),
                           ("tcp_extended_counters", "/proc/net/netstat"),
                           ("interface_counters", "/proc/net/dev"),
                           ("conntrack_counters", "/proc/net/stat/nf_conntrack"),
                           ("softnet_counters", "/proc/net/softnet_stat"),
                           ("socket_memory", "/proc/net/sockstat"),
                           ("memory_pressure", "/proc/pressure/memory")):
            report[name] = self.read(path)
        # Query units before optional commands so missing utilities cannot hide conflicts.
        report["systemd"] = self.systemd()
        watchdog = self.read("/usr/local/bin/vpn-watchdog.sh")
        if watchdog["status"] == "ok":
            digest = hashlib.sha256(watchdog["value"].encode()).hexdigest()
            watchdog = ok({"sha256": digest, "known_source": digest == KNOWN_WATCHDOG})
        report["external_watchdog_source"] = watchdog
        warnings = []
        units = report["systemd"].get("value", {})
        external = [name for name in ("vpn-watchdog.service", "vpn-watchdog.timer")
                    if units.get(name, {}).get("ActiveState") == "active"]
        if external:
            warnings.append("Active external vpn-watchdog: potential competing restart owner; inspect before lifecycle changes.")
            if watchdog.get("value", {}).get("known_source"):
                warnings.append("Known external script restarts inactive x-ui and sing-box without stop intent; caddy when enabled. No data-path health probe.")
        report["warnings"] = warnings
        for name, args in (
            ("qdisc", ("tc", "-s", "qdisc", "show")),
            ("routes_ipv4", ("ip", "-4", "route", "show", "table", "all")),
            ("routes_ipv6", ("ip", "-6", "route", "show", "table", "all")),
            ("rules_ipv4", ("ip", "-4", "rule", "show")),
            ("rules_ipv6", ("ip", "-6", "rule", "show")),
            ("links", ("ip", "-s", "link", "show")),
        ):
            report[name] = self.command(*args)
        return redact(report)


def render_text(report):
    lines = ["TUNA network/resource snapshot (read-only)", report["scope"]]
    for name, result in report.items():
        if name in ("schema_version", "read_only", "scope"):
            continue
        lines.extend(("", name + ":", json.dumps(result, ensure_ascii=False, indent=2)))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    parser.add_argument("--timeout", type=float, default=2, help="seconds per command (0.1..10)")
    parser.add_argument("--budget", type=float, default=20, help="total command budget in seconds (1..60)")
    args = parser.parse_args()
    if not 0.1 <= args.timeout <= 10 or not 1 <= args.budget <= 60:
        parser.error("timeout must be 0.1..10 and budget 1..60")
    report = Collector(timeout=args.timeout, budget=args.budget).collect()
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_text(report))


if __name__ == "__main__":
    main()
