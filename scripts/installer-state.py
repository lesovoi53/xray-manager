#!/usr/bin/env python3
"""Root-only, fixed-scope snapshot/restore. Backups contain secrets: mode 0700.

Package installations and system users are retained. Only managed paths are
restored; service active/enabled state and firewall rules are restored too.
"""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile

CONFIGS = ["/etc/" + p for p in (
    "x-manager", "snell", "mita", "mieru", "openflux", "webdav-tunnel", "tuna-subscriptions")]
BINARIES = ["snell-server", "mita", "openflux", "openflux-volga-check", "webdav-tunnel", "x-manager", "tuna-subscriptions", "tuna-groups", "tuna_connection_groups.py",
            "snell-routing.sh", "wdtt-tproxy.sh", "openflux-routing.sh", "openflux-runner.sh",
            "webdav-tunnel-routing.sh", "webdav-tunnel-runner.sh"]
ALIASES = ["snell", "mieru", "wdtt", "qwdtt", "csqtt", "dns", "cottendns", "masterdns", "ssl", "cert",
           "fw", "firewall", "sub", "tuna", "openflux", "flux", "webdav", "wdav"]
UNITS = ["snell", "mita", "wdtt-tproxy", "openflux@", "webdav-tunnel", "tuna-subscriptions", "volga-cookies"]
SERVICES = [u + ".service" for u in UNITS if not u.endswith("@")] + ["openflux@%d.service" % n for n in range(1, 9)] + ["x-ui.service", "volga-cookies.timer"]
SERVICES = ['tuna-watchdog.timer', 'tuna-watchdog.service'] + SERVICES
PATHS = CONFIGS + ["/usr/local/bin/" + b for b in BINARIES + ["x-" + a for a in ALIASES]]
PATHS += ["/usr/bin/mita", "/usr/local/share/x-manager", "/var/lib/tuna-subscriptions",
          "/etc/x-ui/x-ui.db", "/etc/systemd/system/mita.service.d"] + ["/etc/systemd/system/" + u + ".service" for u in UNITS]
PATHS += ["/etc/systemd/system/volga-cookies.timer"]
WATCHDOG_UNITS = ['tuna-subscriptions','webdav-tunnel','snell','mita','wdtt','csqtt','masterdns','cottendns','x-ui'] + ['openflux@'+str(i) for i in range(1,9)]
PATHS += ['/etc/systemd/system/'+unit+'.service.d' for unit in WATCHDOG_UNITS if unit != 'mita']
PATHS += ['/etc/systemd/system/tuna-watchdog.service', '/etc/systemd/system/tuna-watchdog.timer', '/usr/local/bin/tuna-watchdog.sh']


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def query(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.stdout.strip()


def snell_policy():
    def data(*args):
        return json.loads(subprocess.check_output(args, text=True))
    rules=[r for r in data('ip','-j','-4','rule','show') if r.get('priority')==1988 or
           str(r.get('table'))=='1988' or int(str(r.get('fwmark','0')),0)==0x534e]
    routes=[r for r in data('ip','-j','-4','route','show','table','all') if str(r.get('table'))=='1988']
    marker=Path('/etc/snell/tproxy-state.json')
    owned=marker.is_file() and json.loads(marker.read_text())=={'table':1988,'priority':1988,'mark':0x534e}
    return dict(rules=rules,routes=routes,owned=owned)


def restore_snell_policy(previous, current):
    # No global `ip rule flush`: only the reserved Snell slot may change.
    if previous['rules']==current['rules'] and previous['routes']==current['routes']:
        return
    for value in (previous,current):
        if (value['rules'] or value['routes']) and not value['owned']:
            raise RuntimeError('Snell policy slot changed ownership; refusing rollback over foreign routes')
        if len(value['rules'])>1 or any(r.get('priority')!=1988 or str(r.get('table'))!='1988' or
             int(str(r.get('fwmark','0')),0)!=0x534e or r.get('src','all')!='all' or
             r.get('fwmask','0xffffffff') not in ('0xffffffff',4294967295) for r in value['rules']):
            raise RuntimeError('Unexpected Snell policy rule; manual rollback required')
        if len(value['routes'])>1 or any(r.get('type')!='local' or r.get('dev')!='lo' or
             r.get('dst') not in ('default','0.0.0.0/0') for r in value['routes']):
            raise RuntimeError('Unexpected Snell policy route; manual rollback required')
    if current['rules']:
        run('ip','-4','rule','del','priority','1988','fwmark',str(0x534e),'table','1988')
    if current['routes']:
        run('ip','-4','route','del','local','0.0.0.0/0','dev','lo','table','1988')
    if previous['routes']:
        run('ip','-4','route','add','local','0.0.0.0/0','dev','lo','table','1988')
    if previous['rules']:
        run('ip','-4','rule','add','priority','1988','fwmark',str(0x534e),'table','1988')


def snapshot(dest, config_module):
    state = {"present": [], "services": {}, "paths": list(PATHS), "databases": []}
    state['snell_policy']=snell_policy()
    sys.path.insert(0, str(Path(config_module).parent))
    spec = importlib.util.spec_from_file_location('tuna_backup_config', config_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config_file = Path('/etc/tuna-subscriptions/config.toml')
    subscription_db = '/var/lib/tuna-subscriptions/subscriptions.db'
    if config_file.exists():
        subscription_db = module.load_config(str(config_file))['database']['path']
        if not Path(subscription_db).is_absolute():
            raise ValueError('Subscription database must have an absolute path')
        if subscription_db not in state['paths'] and not subscription_db.startswith('/var/lib/tuna-subscriptions/'):
            state['paths'].append(subscription_db)
    for unit in SERVICES:
        state["services"][unit] = {"active": query("systemctl", "is-active", unit) == "active",
                                   "enabled": query("systemctl", "is-enabled", unit)}
    with open(dest / "iptables", "w") as f:
        run("iptables-save", stdout=f)
    with open(dest / "ip6tables", "w") as f:
        run("ip6tables-save", stdout=f)
    with tarfile.open(dest / "files.tar", "w") as archive:
        for name in state['paths']:
            p = Path(name)
            if p.exists() or p.is_symlink():
                state["present"].append(name)
                archive.add(p, arcname=name.lstrip("/"))
    # Live SQLite backup API includes WAL transactions; never copy a live DB alone.
    for index, name in enumerate(("/etc/x-ui/x-ui.db", subscription_db)):
        if Path(name).is_file():
            with sqlite3.connect("file:" + name + "?mode=ro", uri=True) as src:
                target = dest / ('database-%d.sqlite' % index)
                with sqlite3.connect(target) as dst:
                    src.backup(dst)
                state['databases'].append({'path': name, 'backup': target.name})
    (dest / "state.json").write_text(json.dumps(state))


def restore(dest):
    state = json.loads((dest / "state.json").read_text())
    failures = []
    for unit in SERVICES:
        if query("systemctl", "show", "-p", "LoadState", "--value", unit) != "not-found":
            if subprocess.run(["systemctl", "stop", unit]).returncode:
                raise RuntimeError("Cannot stop " + unit + "; refusing to restore files beneath a running service")
    if 'snell_policy' in state:
        restore_snell_policy(state['snell_policy'], snell_policy())
    for name in state['paths']:
        p = Path(name)
        if p.is_symlink() or p.is_file():
            p.unlink()
        elif p.is_dir():
            shutil.rmtree(p)
    with tarfile.open(dest / "files.tar") as archive:
        # Archive is generated locally in a root-owned 0700 directory.
        for member in archive.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise ValueError("Invalid backup member")
        archive.extractall("/", filter="fully_trusted") if sys.version_info >= (3, 12) else archive.extractall("/")
    for database in state['databases']:
        filename, target = database['backup'], database['path']
        if (dest / filename).exists():
            # Preserve restored ownership/mode while replacing only DB contents.
            with open(dest / filename, "rb") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            for suffix in ("-wal", "-shm"):
                Path(target + suffix).unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    # Transparent Snell routing checks the actual Xray listeners at start.
    # Restore the managed core before dependent services, timers last.
    for unit, previous in sorted(state["services"].items(), key=lambda pair: (pair[0].endswith(".timer"), pair[0] != 'x-ui.service')):
        if previous["enabled"] in ("enabled", "disabled"):
            if subprocess.run(["systemctl", "enable" if previous["enabled"] == "enabled" else "disable", unit]).returncode:
                failures.append(unit + ": enable state")
        elif previous["enabled"] in ("not-found", ""):
            # Remove enable links created by this installation for previously absent units.
            for link in Path("/etc/systemd/system").glob("*.wants/" + unit):
                if link.is_symlink():
                    link.unlink()
        if previous["active"] and subprocess.run(["systemctl", "start", unit]).returncode:
            failures.append(unit + ": start")
    with open(dest / "iptables") as f:
        run("iptables-restore", stdin=f)
    if (dest / "ip6tables").is_file():
        with open(dest / "ip6tables") as f:
            run("ip6tables-restore", stdin=f)
    if 'snell_policy' in state:
        restore_snell_policy(state['snell_policy'], snell_policy())
    if failures:
        raise RuntimeError("Rollback service failures: " + ", ".join(failures))


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Run as root")
    mode, directory = sys.argv[1:3]
    dest = Path(directory).resolve()
    if not str(dest).startswith("/var/backups/x-manager-") or dest.stat().st_uid != 0 or dest.stat().st_mode & 0o077:
        sys.exit("Expected a root-owned private /var/backups/x-manager-* directory")
    if mode == "backup":
        snapshot(dest, sys.argv[3])
    elif mode == "restore":
        restore(dest)
    else:
        sys.exit("Expected backup or restore")
