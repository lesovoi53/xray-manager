#!/usr/bin/env python3
"""Report OpenFlux memory and manage automatic or manual Go soft budgets.

The numeric resources.conf is the only runtime input this helper owns. No channel
credentials are executed or emitted. Recommendations are capacity estimates, not
RSS limits or claims that retained application memory has been repaired.
"""
import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import uuid

MIB = 1024 * 1024
CONFIG = Path("etc/openflux/resources.conf")
STATE = Path("var/lib/x-manager/openflux-resources")
MIN_CHANNEL_MIB = 64


def read(path):
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def parse_limits(text):
    result = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([1-8])=([1-9][0-9]{0,8})MiB", line)
        if not match or match[1] in result:
            raise ValueError("invalid or duplicate channel in managed resources.conf")
        result[match[1]] = int(match[2])
    return result


def configured_channels(root):
    channels = set()
    paths = [(str(i), root / f"etc/openflux/instances/{i}.env") for i in range(1, 9)]
    if not paths[0][1].exists():
        paths.append(("1", root / "etc/openflux/openflux.env"))
    for channel, path in paths:
        # Only identify a nonempty saved URL; never source the shell file.
        for line in read(path).splitlines():
            if re.match(r"^\s*(?:export\s+)?URL=", line):
                value = line.split("=", 1)[1].strip()
                if value not in ("", "''", '""'):
                    channels.add(channel)
    return channels


def limit_mib(value):
    match = re.fullmatch(r"([1-9][0-9]*)(B|KiB|MiB|GiB|TiB)?", value or "")
    if not match:
        return None
    scale = {None: 1, "B": 1, "KiB": 1024, "MiB": MIB, "GiB": 1024 * MIB, "TiB": 1024**2 * MIB}
    return int(match[1]) * scale[match[2]] // MIB


def saved_channel_limit(root, channel):
    path = root / f"etc/openflux/instances/{channel}.env"
    if channel == "1" and not path.exists():
        path = root / "etc/openflux/openflux.env"
    result = None
    for line in read(path).splitlines():
        match = re.fullmatch(r'\s*(?:export\s+)?GOMEMLIMIT=["\']?([0-9]+(?:KiB|MiB|GiB|TiB|B)?)["\']?\s*', line)
        if match:
            result = limit_mib(match[1])
    return result


def systemd_channels(root):
    if root != Path("/"):
        return {}, ["runtime systemd inspection disabled for an isolated filesystem root"]
    result, warnings = {}, []
    props = "ActiveState,MainPID,MemoryCurrent,MemoryPeak,MemoryHigh,MemoryMax,Environment"
    try:
        run = subprocess.run(
            ["systemctl", "show", *[f"openflux@{i}.service" for i in range(1, 9)],
             f"--property=Id,{props}"], text=True, capture_output=True, timeout=15)
        if run.returncode:
            return {}, ["systemd runtime memory inspection unavailable"]
        for block in run.stdout.strip().split("\n\n"):
            row = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            match = re.fullmatch(r"openflux@([1-8])\.service", row.get("Id", ""))
            if not match:
                continue
            env = {}
            for item in shlex.split(row.pop("Environment", "")):
                key, sep, value = item.partition("=")
                if sep and key == "GOMEMLIMIT":
                    env[key] = value
            pid = row.get("MainPID", "0")
            runtime_limit = None
            process_memory = {}
            if pid.isdigit() and int(pid):
                try:
                    for item in (root / f"proc/{pid}/environ").read_bytes().split(b"\0"):
                        if item.startswith(b"GOMEMLIMIT="):
                            runtime_limit = item.split(b"=", 1)[1].decode("ascii", errors="replace")
                except OSError:
                    pass
                try:
                    for line in read(root / f"proc/{pid}/status").splitlines():
                        field = re.fullmatch(r"(VmRSS|VmSize|VmSwap):\s+(\d+) kB", line)
                        if field:
                            process_memory[field[1] + "Bytes"] = int(field[2]) * 1024
                except OSError:
                    pass
            result[match[1]] = {
                "active_state": row.get("ActiveState", "unknown"),
                "runtime_gomemlimit": runtime_limit,
                "unit_gomemlimit": env.get("GOMEMLIMIT"),
                **process_memory,
                **{key: row.get(key) for key in ("MemoryCurrent", "MemoryPeak", "MemoryHigh", "MemoryMax")},
            }
    except (OSError, subprocess.TimeoutExpired, ValueError):
        warnings.append("systemd runtime memory inspection unavailable")
    return result, warnings


def capacity(root):
    info = {}
    for line in read(root / "proc/meminfo").splitlines():
        match = re.fullmatch(r"(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+) kB", line)
        if match:
            info[match[1]] = int(match[2]) * 1024
    if not info.get("MemTotal"):
        raise ValueError("cannot read MemTotal from /proc/meminfo")
    # Detect a container's cgroup v2 ceiling and every visible parent. Swap is
    # reported but deliberately not counted as capacity for these Go budgets.
    ceilings = [info["MemTotal"]]
    mounts = [root / "sys/fs/cgroup"]
    for line in read(root / "proc/self/cgroup").splitlines():
        if line.startswith("0::"):
            relative = Path(line[3:].lstrip("/"))
            if ".." not in relative.parts:
                current = root / "sys/fs/cgroup" / relative
                while current not in mounts and current.is_relative_to(root / "sys/fs/cgroup"):
                    mounts.append(current)
                    current = current.parent
    for mount in mounts:
        value = read(mount / "memory.max").strip()
        if value.isdigit() and int(value) > 0:
            ceilings.append(int(value))
    info["effective_bytes"] = min(ceilings)
    return info


def build_plan(root, total_mib=None, reserve_os_mib=None, reserve_other_mib=None):
    mem = capacity(root)
    runtime, warnings = systemd_channels(root)
    configured = configured_channels(root)
    managed = parse_limits(read(root / CONFIG))
    active = {c for c, row in runtime.items() if row["active_state"] in ("active", "activating", "reloading")}
    # Previously managed channels remain reserved even when temporarily stopped
    # or removed; otherwise a later restart could silently overcommit the plan.
    channels = sorted(configured | active | managed.keys(), key=int)
    effective_mib = mem["effective_bytes"] // MIB
    os_mib = reserve_os_mib if reserve_os_mib is not None else max(256, (effective_mib + 4) // 5)
    other_mib = reserve_other_mib if reserve_other_mib is not None else max(256, (effective_mib * 15 + 99) // 100)
    remaining = max(0, effective_mib - os_mib - other_mib)
    # Leave 25% of the remainder for non-Go memory and estimate error. These
    # explicit policy defaults can be tuned with measured service footprints.
    budget = total_mib if total_mib is not None else remaining * 3 // 4
    if budget < 0 or os_mib < 0 or other_mib < 0:
        raise ValueError("memory budgets and reserves must be nonnegative")
    if budget > remaining:
        raise ValueError("total Go budget exceeds memory left after OS/other-service reserves")
    allocation = {}
    if channels:
        per, extra = divmod(budget, len(channels))
        allocation = {c: per + (i < extra) for i, c in enumerate(channels)}
        if total_mib is None:
            for channel in channels:
                row = runtime.get(channel, {})
                current = (managed.get(channel) or limit_mib(row.get("runtime_gomemlimit"))
                           or saved_channel_limit(root, channel) or limit_mib(row.get("unit_gomemlimit")) or 150)
                # Spare RAM alone is not evidence that a healthy process needs
                # a larger target. An explicit --total-mib opts into resizing.
                allocation[channel] = min(allocation[channel], current)
    can_apply = bool(channels) and min(allocation.values(), default=0) >= MIN_CHANNEL_MIB
    if not channels:
        warnings.append("no configured, active, or previously managed channels")
    elif not can_apply:
        warnings.append("less than 64 MiB per channel: reduce channel count or revise measured reserves before apply")
    if sum(managed.values()) > remaining:
        warnings.append("saved soft budgets exceed capacity left after reserves")
    if managed and (configured | active) - managed.keys():
        warnings.append("new channels have no managed budget; review the aggregate plan before their next start")
    warnings.append("GOMEMLIMIT is a soft Go runtime target, not an RSS cap or a memory-leak fix")
    warnings.append("OS/other-service reserves are estimates; other-service reserve includes Xray and panels")
    if total_mib is None:
        warnings.append("default recommendations preserve lower existing targets (150 MiB compatibility fallback); explicit --total-mib permits increasing them")
    if active - configured:
        warnings.append("active channels without a detected saved URL are included in the budget")
    return {
        "schema": 1, "memory": mem, "channels": channels,
        "configured_channels": sorted(configured, key=int), "active_channels": sorted(active, key=int),
        "reserve_os_mib": os_mib, "reserve_other_mib": other_mib,
        "non_go_headroom_mib": remaining - sum(allocation.values()),
        "capacity_go_budget_mib": budget,
        "total_go_budget_mib": sum(allocation.values()), "recommended_mib": allocation,
        "managed_mib": managed, "runtime": runtime, "can_apply": can_apply,
        "warnings": warnings, "restart_required_to_activate": True,
    }


def safe_path(root, relative):
    target = root / relative
    current = target
    while current != root:
        if current.is_symlink():
            raise ValueError("refusing symlink in managed resource path")
        current = current.parent
    return target


def atomic_write(path, data, mode=0o644, owner=None):
    fd, temporary = tempfile.mkstemp(prefix=".resources-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
            if owner is not None and hasattr(os, "fchown"):
                os.fchown(stream.fileno(), *owner)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def transaction(root):
    directory = safe_path(root, STATE)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = safe_path(root, STATE / ".lock")
    with lock.open("a") as stream:
        try:
            import fcntl
        except ImportError:
            raise ValueError("apply and rollback require Linux file locking") from None
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def digest(data):
    return None if data is None else hashlib.sha256(data).hexdigest()


def apply_plan(root, plan, automatic=False, locked=False):
    if not plan["can_apply"]:
        raise ValueError("no safe channel budget to apply; review report warnings")
    with (contextlib.nullcontext() if locked else transaction(root)):
        target = safe_path(root, CONFIG)
        target.parent.mkdir(parents=True, exist_ok=True)
        before = target.read_bytes() if target.exists() else None
        if before is not None:
            parse_limits(before.decode("utf-8"))
        if parse_limits(before.decode("utf-8") if before is not None else "") != plan["managed_mib"]:
            raise ValueError("managed limits changed after planning; regenerate the plan")
        if not configured_channels(root).issubset(plan["channels"]):
            raise ValueError("channel inventory changed after planning; regenerate the plan")
        data = (("# X-Manager automatic Go soft budgets.\n" if automatic else "# X-Manager managed Go soft budgets; no hard RSS cap.\n") + "".join(
            f"{c}={value}MiB\n" for c, value in plan["recommended_mib"].items())).encode()
        if data == before:
            return {"changed": False, "snapshot_id": None, "restart_performed": False}
        previous = target.stat() if before is not None else None
        snapshot_id = str(uuid.uuid4())
        snapshot = {"schema": 1, "before": None if before is None else base64.b64encode(before).decode(),
                    "after_sha256": digest(data), "mode": previous.st_mode & 0o777 if previous else 0o644,
                    "uid": previous.st_uid if previous else os.getuid(),
                    "gid": previous.st_gid if previous else os.getgid()}
        backup = safe_path(root, STATE / f"{snapshot_id}.json")
        atomic_write(backup, json.dumps(snapshot, sort_keys=True).encode(), 0o600)
        atomic_write(target, data, snapshot["mode"], (snapshot["uid"], snapshot["gid"]))
        return {"changed": True, "snapshot_id": snapshot_id, "restart_performed": False,
                "note": "saved for the next channel start; existing processes retain their current limits"}


def rollback(root, snapshot_id):
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", snapshot_id):
        raise ValueError("invalid snapshot ID")
    with transaction(root):
        snapshot = json.loads(safe_path(root, STATE / f"{snapshot_id}.json").read_text())
        if snapshot.get("schema") != 1:
            raise ValueError("unsupported snapshot schema")
        target = safe_path(root, CONFIG)
        current = target.read_bytes() if target.exists() else None
        before = None if snapshot["before"] is None else base64.b64decode(snapshot["before"], validate=True)
        if before is not None:
            parse_limits(before.decode("utf-8"))
        if current == before:
            return {"changed": False, "restart_performed": False}
        if digest(current) != snapshot["after_sha256"]:
            raise ValueError("managed limits changed since this snapshot; refusing to overwrite newer edits")
        if before is None:
            target.unlink()
        else:
            atomic_write(target, before, int(snapshot["mode"]), (int(snapshot["uid"]), int(snapshot["gid"])))
        return {"changed": True, "restart_performed": False,
                "note": "previous bytes restored; running channels were not restarted"}


def auto_apply(root):
    with transaction(root):
        target = safe_path(root, CONFIG)
        if target.exists() and not read(target).startswith("# X-Manager automatic Go soft budgets.\n"):
            parse_limits(read(target))
            return {"changed": False, "restart_performed": False,
                    "note": "Сохранён пользовательский бюджет памяти."}
        plan = build_plan(root)
        if "systemd runtime memory inspection unavailable" in plan["warnings"]:
            raise ValueError("Не удалось прочитать состояние systemd; бюджет памяти не изменён")
        if not plan["channels"]:
            return {"changed": False, "restart_performed": False, "note": "Настроенных каналов нет."}
        result = apply_plan(root, plan, automatic=True, locked=True)
        result["note"] = ("Автоматический бюджет сохранён; действует при запуске канала."
                          if result["changed"] else "Автоматический бюджет уже настроен; изменений нет.")
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("report", "plan", "apply", "rollback", "auto"), nargs="?", default="report")
    parser.add_argument("snapshot_id", nargs="?")
    parser.add_argument("--root", type=Path, default=Path("/"), help="isolated filesystem root for local acceptance")
    parser.add_argument("--json", action="store_true")
    for name in ("total", "reserve-os", "reserve-other"):
        parser.add_argument(f"--{name}-mib", type=int)
    args = parser.parse_args(argv)
    if args.command in ("auto", "rollback") and any(value is not None for value in
            (args.total_mib, args.reserve_os_mib, args.reserve_other_mib)):
        parser.error("memory options are only accepted by report, plan and apply")
    if args.command != "rollback" and args.snapshot_id:
        parser.error("unexpected snapshot ID")
    root = args.root.absolute()
    if root.is_symlink():
        parser.error("filesystem root must not be a symlink")
    try:
        if args.command == "auto":
            result = auto_apply(root)
            print(json.dumps(result, ensure_ascii=False) if args.json else result["note"])
            return 0
        if args.command == "rollback":
            if not args.snapshot_id:
                parser.error("rollback requires the snapshot ID returned by apply")
            result = rollback(root, args.snapshot_id)
        else:
            if args.snapshot_id:
                parser.error("unexpected snapshot ID")
            result = build_plan(root, args.total_mib, args.reserve_os_mib, args.reserve_other_mib)
            if args.command == "apply":
                result = {"plan": result, "transaction": apply_plan(root, result)}
        if args.json or args.command in ("apply", "rollback"):
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("ПАМЯТЬ OPENFLUX\n")
            print("Режим: " + ("автоматический" if read(root / CONFIG).startswith("# X-Manager automatic") else "ручной бюджет" if (root / CONFIG).exists() else "автоматическая настройка при следующем запуске"))
            print(f"Доступно серверу: {result['memory']['effective_bytes'] // MIB} МиБ")
            print(f"Настроено каналов: {len(result['channels'])}")
            print(f"Резерв для ОС: {result['reserve_os_mib']} МиБ")
            print(f"Резерв для Xray и других служб: {result['reserve_other_mib']} МиБ")
            print(f"Рекомендуемый бюджет OpenFlux: {result['total_go_budget_mib']} МиБ")
            print(f"Дополнительный запас: {result['non_go_headroom_mib']} МиБ")
            def mib(value):
                try:return f"{int(value) / MIB:.1f} МиБ"
                except (ValueError, TypeError):return "нет данных"
            for channel in result["channels"]:
                row = result["runtime"].get(channel, {})
                saved = result['managed_mib'].get(channel)
                runtime = limit_mib(row.get('runtime_gomemlimit'))
                print(f"\nКанал {channel}")
                print(f"  Занято процессом (RAM): {mib(row.get('VmRSSBytes'))}")
                print(f"  Учтено системой для службы: {mib(row.get('MemoryCurrent'))}")
                print("  Текущий мягкий лимит Go: " + (str(runtime)+' МиБ' if runtime is not None else 'нет данных'))
                print("  Сохранённый бюджет: " + (str(saved)+' МиБ' if saved is not None else 'не настроен'))
                print(f"  Рекомендуется: {result['recommended_mib'][channel]} МиБ")
                if saved is not None and runtime is not None and saved != runtime:
                    print("  Сохранённый лимит вступит в силу после следующего запуска канала.")
            print("\nРасчёт автоматический. Этот экран только показывает состояние.")
            if not (root / CONFIG).exists() or read(root / CONFIG).startswith("# X-Manager automatic"):
                print("Бюджет сохраняется автоматически при установке и перед запуском канала.")
            else:
                print("Ручной бюджет сохранён; автоматика его не изменяет.")
            print("Изменить вручную: «Диагностика и ресурсы → Настроить общий бюджет памяти OpenFlux».")
            if "systemd runtime memory inspection unavailable" in result["warnings"]:
                print("ВНИМАНИЕ: Не удалось прочитать состояние systemd; данные работающих каналов недоступны.")
            if sum(result['managed_mib'].values()) > max(0, result['memory']['effective_bytes'] // MIB - result['reserve_os_mib'] - result['reserve_other_mib']):
                print("ВНИМАНИЕ: сохранённый бюджет превышает доступную память после резервов.")
            if result['managed_mib'] and set(result['channels']) - result['managed_mib'].keys():
                print("Есть каналы без сохранённого бюджета: перед запуском требуется пересчёт.")
            print("Сохранённый бюджет действует со следующего запуска канала.")
            print("Это мягкий лимит памяти Go: весь процесс может занимать больше.")
            print("Резервы ОС и других служб — оценка. Работающие службы не перезапускались.")
            if not result['can_apply']:
                print("ВНИМАНИЕ: безопасного бюджета для применения нет — проверьте число каналов и объём RAM.")
            if set(result['active_channels'])-set(result['configured_channels']):
                print("Учтены также работающие каналы без найденной сохранённой ссылки.")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"OpenFlux resources: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
