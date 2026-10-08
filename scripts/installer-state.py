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
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
import re
import tempfile
from contextlib import closing

EXTERNAL_WATCHDOGS = ('vpn-watchdog.timer', 'vpn-watchdog.service')
MAINTENANCE = Path('/var/lib/x-manager/maintenance-watchdog.json')


def watchdog_state(unit):
    result = subprocess.run(['systemctl', 'show', unit,
                             '--property=LoadState,ActiveState,UnitFileState'],
                            capture_output=True, text=True, timeout=30)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if result.returncode or values.get('LoadState') not in ('loaded', 'not-found', 'masked') or values.get('ActiveState') not in ('active', 'inactive', 'failed'):
        raise RuntimeError('Cannot verify stable external watcher state: '+unit)
    return values


def watchdog_preflight():
    if MAINTENANCE.exists():
        raise RuntimeError('Interrupted watchdog maintenance. Inspect the saved backup and run install.sh --recover-watchdog before retrying: '+str(MAINTENANCE))
    for unit in EXTERNAL_WATCHDOGS:
        watchdog_state(unit)


def watchdog_save(value):
    MAINTENANCE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.watchdog-', dir=MAINTENANCE.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, MAINTENANCE)
        watchdog_sync()
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def watchdog_sync():
    fd = os.open(MAINTENANCE.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def watchdog_command(action, unit):
    result = subprocess.run(['systemctl', action, unit], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Cannot '+action+' external watcher '+unit+'; maintenance marker retained')


def watchdog_pause(dest):
    watchdog_preflight()
    # A complete backup must exist before either external unit is stopped.
    json.loads((dest/'state.json').read_text())
    if not (dest/'files.tar').is_file():
        raise RuntimeError('Complete backup required before watchdog maintenance')
    previous = {unit: watchdog_state(unit) for unit in EXTERNAL_WATCHDOGS}
    watchdog_save({'version': 1, 'backup': str(dest), 'units': previous})
    for unit in EXTERNAL_WATCHDOGS:  # Timer first: do not launch another service run.
        if previous[unit]['ActiveState'] == 'active':
            watchdog_command('stop', unit)
    check_external_watchdog()


def watchdog_resume():
    if not MAINTENANCE.exists():
        return
    saved = json.loads(MAINTENANCE.read_text())
    if saved.get('version') != 1 or set(saved.get('units', {})) != set(EXTERNAL_WATCHDOGS):
        raise RuntimeError('Invalid watchdog maintenance marker; manual recovery required')
    # Refuse concurrent policy changes instead of enabling/unmasking foreign units.
    for unit in EXTERNAL_WATCHDOGS:
        current, previous = watchdog_state(unit), saved['units'][unit]
        if any(current.get(key) != previous.get(key) for key in ('LoadState', 'UnitFileState')):
            raise RuntimeError('External watcher policy changed during maintenance: '+unit)
        if previous['ActiveState'] != 'active' and current['ActiveState'] == 'active':
            raise RuntimeError('External watcher activated outside maintenance: '+unit)
        if previous['ActiveState'] == 'active' and any(Path(base, unit).exists() for base in (
                '/etc/x-manager/service-control/off', '/run/x-manager/service-control/stopped')):
            raise RuntimeError('External watcher manually inhibited; refusing to resume: '+unit)
    for unit in reversed(EXTERNAL_WATCHDOGS):  # Service before timer.
        previous = saved['units'][unit]
        if previous['ActiveState'] == 'active' and watchdog_state(unit)['ActiveState'] != 'active':
            watchdog_command('start', unit)
            if watchdog_state(unit)['ActiveState'] != 'active':
                raise RuntimeError('External watcher did not become active: '+unit)
    MAINTENANCE.unlink()
    watchdog_sync()

CONFIGS = ["/etc/" + p for p in (
    "x-manager", "snell", "snell6", "mita", "mieru", "openflux", "webdav-tunnel", "tuna-subscriptions")]
BINARIES = ["snell-server", "mita", "openflux", "openflux-volga-check", "webdav-tunnel", "x-manager", "tuna-subscriptions", "tuna-groups", "tuna_connection_groups.py",
            "snell-routing.sh", "wdtt-tproxy.sh", "openflux-routing.sh", "openflux-runner.sh",
            "webdav-tunnel-routing.sh", "webdav-tunnel-runner.sh"]
ALIASES = ["snell", "mieru", "wdtt", "qwdtt", "csqtt", "dns", "cottendns", "masterdns", "ssl", "cert",
           "fw", "firewall", "sub", "tuna", "openflux", "flux", "webdav", "wdav"]
UNITS = ["snell", "mita", "wdtt-tproxy", "openflux@", "webdav-tunnel", "tuna-subscriptions", "volga-cookies"]
SERVICES = [u + ".service" for u in UNITS if not u.endswith("@")] + ["openflux@%d.service" % n for n in range(1, 9)] + ["x-ui.service", "volga-cookies.timer"]
SERVICES = ['tuna-watchdog.timer', 'tuna-watchdog.service'] + SERVICES
SERVICES += ['tuna-healthcheck.timer', 'tuna-healthcheck.service'] + ['snell6@%d.service' % n for n in range(1, 9)]
PATHS = CONFIGS + ["/usr/local/bin/" + b for b in BINARIES + ["x-" + a for a in ALIASES]]
PATHS += ["/usr/bin/mita", "/usr/local/share/x-manager", "/var/lib/tuna-subscriptions",
          "/etc/x-ui/x-ui.db", "/etc/systemd/system/mita.service.d"] + ["/etc/systemd/system/" + u + ".service" for u in UNITS]
PATHS += ["/etc/systemd/system/volga-cookies.timer"]
PATHS += ['/etc/systemd/system/snell6@.service', '/usr/local/lib/x-manager/snell6',
          '/etc/systemd/system/tuna-healthcheck.service', '/etc/systemd/system/tuna-healthcheck.timer']
# Health attempt counters are deliberately not rolled back: restoring an older
# counter would silently replenish the persistent automatic-restart budget.
WATCHDOG_UNITS = ['tuna-subscriptions','webdav-tunnel','snell','mita','wdtt','csqtt','masterdns','cottendns','x-ui','xray'] + ['openflux@'+str(i) for i in range(1,9)]
WATCHDOG_UNITS += ['snell6@'+str(i) for i in range(1,9)]
PATHS += ['/etc/systemd/system/'+unit+'.service.d' for unit in WATCHDOG_UNITS if unit != 'mita']
PATHS += ['/etc/systemd/system/tuna-watchdog.service', '/etc/systemd/system/tuna-watchdog.timer', '/usr/local/bin/tuna-watchdog.sh']
# Lifecycle guards include explicit opt-in external VPN services. Do not copy or
# replace their configuration/binaries; preserve only our guard and unit state.
LIFECYCLE_UNITS = ['wdtt','csqtt','masterdns','cottendns','sing-box','caddy','xray','vpn-watchdog','fail2ban']
SERVICES += [u+'.service' for u in LIFECYCLE_UNITS if u+'.service' not in SERVICES]
SERVICES += ['vpn-watchdog.timer']
PATHS += ['/run/x-manager/service-control']
PATHS += ['/var/lib/x-manager/openflux-resources', '/var/lib/x-manager/network-profile',
          '/etc/sysctl.d/90-tuna-network.conf']
for unit in SERVICES:
    guard='/etc/systemd/system/'+unit+'.d/95-tuna-service-control.conf'
    if not any(guard.startswith(p.rstrip('/')+'/') for p in PATHS):
        PATHS.append(guard)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def query(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.stdout.strip()


def check_external_watchdog():
    """External pollers must not revive services while their files are restored."""
    for unit in EXTERNAL_WATCHDOGS:
        if watchdog_state(unit)['ActiveState'] == 'active':
            raise RuntimeError('External watcher '+unit+' is running during maintenance; refusing managed changes')


def wait_snell_gateways(timeout=30):
    """Type=simple panel startup does not mean its child Xray is listening yet."""
    mode = Path('/etc/snell/routing.mode')
    if not mode.exists() or mode.read_text().strip() != 'xray':
        return
    text = Path('/etc/x-manager/gateways.env').read_text()
    ports = {}
    for key in ('XRAY_REDIRECT_PORT', 'XRAY_TPROXY_PORT'):
        match = re.search(r'^'+key+r'=["\']?([0-9]+)["\']?\s*$', text, re.M)
        if not match or not 1 <= int(match[1]) <= 65535:
            raise RuntimeError('Cannot validate restored gateway: '+key)
        ports[key] = int(match[1])
    expected = '0100007F:'+format(ports['XRAY_TPROXY_PORT'], '04X')
    deadline = time.monotonic()+timeout
    while True:
        try:
            udp = any(len(row.split()) > 1 and row.split()[1] == expected
                      for row in Path('/proc/net/udp').read_text().splitlines()[1:])
            if udp:
                with socket.create_connection(('127.0.0.1', ports['XRAY_REDIRECT_PORT']), timeout=.5):
                    return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('Restored Xray TCP/UDP gateways not ready; Snell left stopped')
        time.sleep(.25)


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


def validate_backup(dest):
    state = json.loads((dest/'state.json').read_text())
    for key in ('services', 'paths', 'databases'):
        if key not in state:
            raise ValueError('Incomplete backup: '+key)
    with tarfile.open(dest/'files.tar') as archive:
        for member in archive.getmembers():
            if member.name.startswith('/') or '..' in Path(member.name).parts:
                raise ValueError('Invalid backup member')
    if not (dest/'iptables').is_file():
        raise ValueError('Incomplete firewall backup')
    # The tar contains a raw copy of the live main DB, which can omit committed
    # WAL transactions. Only the SQLite backup API snapshot is restorable.
    if not isinstance(state['databases'], list):
        raise ValueError('Invalid SQLite snapshot metadata')
    for database in state['databases']:
        if (not isinstance(database, dict) or not isinstance(database.get('backup'), str)
                or not re.fullmatch(r'database-[0-9]+\.sqlite', database['backup'])
                or not isinstance(database.get('path'), str) or not Path(database['path']).is_absolute()):
            raise ValueError('Invalid SQLite snapshot metadata')
        snapshot = dest/database['backup']
        try:
            if snapshot.is_symlink() or not snapshot.is_file():
                raise ValueError('Missing or invalid SQLite snapshot: '+database['backup'])
            with snapshot.open('rb') as stream:
                if stream.read(16) != b'SQLite format 3\x00':
                    raise ValueError('Invalid SQLite snapshot: '+database['backup'])
            # immutable prevents journal creation/recovery in the backup itself.
            with closing(sqlite3.connect(snapshot.resolve().as_uri()+'?mode=ro&immutable=1', uri=True)) as connection:
                if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise ValueError('Corrupt SQLite snapshot: '+database['backup'])
        except (OSError, sqlite3.Error) as error:
            raise ValueError('Unreadable or corrupt SQLite snapshot: '+database['backup']) from error
    return state


def watcher_policy_files(root=Path('/')):
    return [root / base.lstrip('/') / (unit+suffix) for unit in EXTERNAL_WATCHDOGS for base, suffix in (
        ('/etc/x-manager/service-control/off', ''),
        ('/run/x-manager/service-control/stopped', ''),
        ('/etc/systemd/system', '.d/95-tuna-service-control.conf'))]


def save_watcher_policy(root=Path('/')):
    """Historical rollback must not revive a watcher disabled after that backup."""
    policy = root/'etc/x-manager/service-control/state.json'
    data = json.loads(policy.read_text()) if policy.exists() else {'units': {}}
    entries = {unit: data['units'].get(unit) for unit in EXTERNAL_WATCHDOGS}
    files = {}
    for path in watcher_policy_files(root):
        if path.is_symlink():
            raise RuntimeError('Symlink in external watcher policy; manual recovery required: '+str(path))
        files[path] = (path.read_bytes(), path.stat()) if path.exists() else None
    return entries, files


def restore_watcher_policy(saved, root=Path('/')):
    entries, files = saved
    policy = root/'etc/x-manager/service-control/state.json'
    if policy.exists() or any(value is not None for value in entries.values()):
        data = json.loads(policy.read_text()) if policy.exists() else {'version': 1, 'units': {}}
        for unit, entry in entries.items():
            data['units'].pop(unit, None)
            if entry is not None:
                data['units'][unit] = entry
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text(json.dumps(data))
        policy.chmod(0o600)
    for path, value in files.items():
        if value is None:
            path.unlink(missing_ok=True)
        else:
            content, previous = value
            path.parent.mkdir(parents=True, exist_ok=True)
            path.unlink(missing_ok=True)
            path.write_bytes(content)
            path.chmod(previous.st_mode & 0o777)
            os.chown(path, previous.st_uid, previous.st_gid)


def restore(dest):
    # Keep this guard before snapshot reads, service stops and every file write.
    check_external_watchdog()
    state = validate_backup(dest)
    watcher_policy = save_watcher_policy()
    failures = []
    for unit in SERVICES:
        if unit in EXTERNAL_WATCHDOGS:
            continue  # Resumed separately after all files/firewall are restored.
        if unit in [u+'.service' for u in LIFECYCLE_UNITS] + ['vpn-watchdog.timer']:
            previous = state['services'].get(unit)
            if previous is None or previous.get('active'):
                # No external service binary/config belongs to this transaction.
                continue
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
        # Root-owned backup preserves absolute admin symlinks and file metadata.
        # Feature detection also handles Debian's Python 3.11 filter backport.
        if hasattr(tarfile, 'fully_trusted_filter'):
            archive.extractall("/", filter='fully_trusted')
        else:
            archive.extractall("/")
    restore_watcher_policy(watcher_policy)
    for database in state['databases']:
        filename, target = database['backup'], database['path']
        # Preserve restored ownership/mode while replacing only DB contents.
        # Disappearance after validation remains fatal; never use the raw tar DB.
        with open(dest / filename, "rb") as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
        for suffix in ("-wal", "-shm"):
            Path(target + suffix).unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    # Transparent Snell routing checks the actual Xray listeners at start.
    # Restore the managed core before dependent services, timers last.
    for unit, previous in sorted(state["services"].items(), key=lambda pair: (pair[0].endswith(".timer"), pair[0] != 'x-ui.service')):
        if unit in EXTERNAL_WATCHDOGS:
            continue
        if previous["enabled"] in ("enabled", "disabled"):
            if subprocess.run(["systemctl", "enable" if previous["enabled"] == "enabled" else "disable", unit]).returncode:
                failures.append(unit + ": enable state")
        elif previous["enabled"] in ("not-found", ""):
            # Remove enable links created by this installation for previously absent units.
            for link in Path("/etc/systemd/system").glob("*.wants/" + unit):
                if link.is_symlink():
                    link.unlink()
        if previous["active"]:
            if unit == 'snell.service':
                try:
                    wait_snell_gateways()
                except (OSError, RuntimeError) as error:
                    failures.append(unit+': '+str(error))
                    continue
            if subprocess.run(["systemctl", "start", unit]).returncode:
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
    mode = sys.argv[1]
    if mode == 'watchdog-check':
        watchdog_preflight()
        sys.exit(0)
    if mode == 'watchdog-resume':
        watchdog_resume()
        sys.exit(0)
    directory = sys.argv[2]
    dest = Path(directory).resolve()
    if not str(dest).startswith("/var/backups/x-manager-") or dest.stat().st_uid != 0 or dest.stat().st_mode & 0o077:
        sys.exit("Expected a root-owned private /var/backups/x-manager-* directory")
    if mode == "backup":
        snapshot(dest, sys.argv[3])
    elif mode == "restore":
        restore(dest)
    elif mode == 'watchdog-pause':
        watchdog_pause(dest)
    elif mode == 'validate':
        validate_backup(dest)
    else:
        sys.exit("Expected backup or restore")
