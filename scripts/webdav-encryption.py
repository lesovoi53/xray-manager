#!/usr/bin/env python3
"""Apply WebDAV encryption and synchronize only matching catalog endpoints.

Run as root. No credentials or subscription URLs are printed.
"""
import argparse
import datetime
import fcntl
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time


def storage_key(value):
    return (value['url'].rstrip('/'), value['username'], value['password'])


def synchronize(db_path, candidates, module, backup_dir):
    """Update enc/fingerprint/revisions atomically; leave all other fields intact."""
    if not Path(db_path).is_file():
        raise RuntimeError('TUNA database is missing')
    allowed = {storage_key(s) for c in candidates for s in [c, *c.get('backends', [])]}
    values = {c['enc'] for c in candidates}
    if len(values) != 1:
        raise RuntimeError('Ambiguous encryption state')
    enc = values.pop()
    db = sqlite3.connect(db_path, timeout=30)
    db.row_factory = sqlite3.Row
    try:
        # Backup through a separate read connection while the write reservation
        # prevents concurrent writers. This includes committed WAL contents.
        db.execute('BEGIN IMMEDIATE')
        # Root must not leave new WAL files inaccessible to the service account.
        st = Path(db_path).stat()
        for suffix in ('-wal', '-shm'):
            sidecar = Path(str(db_path) + suffix)
            if sidecar.exists() and os.geteuid() == 0:
                os.chown(sidecar, st.st_uid, st.st_gid)
        changes = []
        for row in db.execute('SELECT * FROM webdav_connections'):
            item = dict(row)
            item['backends'] = json.loads(item['backends_json'])
            if not all(storage_key(s) in allowed for s in [item, *item['backends']]):
                continue
            if item['enc'] == enc:
                continue
            item['enc'] = enc
            ok, _, _ = module.serialize_webdav_uri(item)
            if not ok:
                raise RuntimeError('Matching WebDAV connection failed validation')
            changes.append((item['id'], module.compute_webdav_canonical_fingerprint(item)))
        if not changes:
            db.rollback()
            return 0
        with sqlite3.connect(db_path) as source, sqlite3.connect(str(backup_dir / 'tuna.db')) as target:
            source.backup(target)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        users = set()
        for cid, fingerprint in changes:
            users.update(r[0] for r in db.execute('SELECT user_id FROM user_webdav_selection WHERE connection_id=? AND enabled=1', (cid,)))
            db.execute('UPDATE webdav_connections SET enc=?, fingerprint=?, revision=revision+1, updated_at=? WHERE id=?', (enc, fingerprint, now, cid))
        for uid in users:
            db.execute('UPDATE user_webdav_config SET revision=revision+1, updated_at=? WHERE user_id=?', (now, uid))
            db.execute('UPDATE users SET revision=revision+1, updated_at=? WHERE id=?', (now, uid))
        db.commit()
        return len(changes)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def active():
    return run('systemctl', 'show', 'webdav-tunnel', '-p', 'ActiveState', '--value') == 'active'


def verify_process(enc):
    """Check actual relay argv, including the multi-mode runner's child."""
    pid = int(run('systemctl', 'show', 'webdav-tunnel', '-p', 'MainPID', '--value'))
    pids = [pid] if pid else []
    for p in list(pids):
        children = Path(f'/proc/{p}/task/{p}/children')
        if children.exists():
            pids.extend(int(x) for x in children.read_text().split())
    for p in pids:
        try:
            args = Path(f'/proc/{p}/cmdline').read_bytes().split(b'\0')
        except FileNotFoundError:
            continue
        if args[0] != b'/usr/local/bin/webdav-tunnel' or b'-storage-only' in args:
            continue
        actual = b'-enc' in args or b'-enc=true' in args or b'-enc=1' in args
        if actual == bool(enc):
            return
    raise RuntimeError('Running WebDAV relay does not match requested encryption')


def atomic_config(path, data):
    st = path.stat()
    fd, name = tempfile.mkstemp(prefix='.enc-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), st.st_mode & 0o777)
            os.fchown(out.fileno(), st.st_uid, st.st_gid)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def apply_change(env, value, restart, sync):
    previous = env.read_bytes()
    changed = False
    try:
        if value is not None:
            text = re.sub(r'(?m)^\s*(?:export\s+)?WEBDAV_ENC=.*(?:\n|$)', '', previous.decode('utf-8'))
            atomic_config(env, (text.rstrip('\n')+'\nWEBDAV_ENC="'+value+'"\n').encode())
            changed = True
            restart()
        return sync()
    except Exception:
        if changed:
            atomic_config(env, previous)
            restart()
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--set', choices=('true', 'false'))
    parser.add_argument('--server-ip')
    parser.add_argument('--if-active', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run as root')
    os.umask(0o077)
    with open('/run/lock/x-manager-webdav-enc.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not active():
            if args.if_active and args.set is None:
                print('WebDAV is stopped: encryption synchronization deferred until start')
                return
            raise RuntimeError('Start WebDAV before changing encryption')
        sys.path.insert(0, '/usr/local/bin')
        loader = importlib.machinery.SourceFileLoader('tuna_enc', '/usr/local/bin/tuna-subscriptions')
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        cfg = module.load_config('/etc/tuna-subscriptions/config.toml')
        # Include local addresses and an explicitly supplied public/NAT address.
        hosts = {a['local'] for i in json.loads(run('ip', '-j', 'address', 'show')) for a in i.get('addr_info', []) if a.get('family') == 'inet'}
        if args.server_ip:
            hosts.add(args.server_ip)
        env = Path('/etc/webdav-tunnel/config.env')
        previous = env.read_bytes()
        backup = Path(tempfile.mkdtemp(prefix='webdav-enc-', dir='/var/backups'))
        (backup / 'config.env').write_bytes(previous)
        def restart():
            subprocess.run(['systemctl', 'restart', 'webdav-tunnel'], check=True)
            time.sleep(1)

        def sync():
            candidates = []
            for host in sorted(hosts):
                ok, _, candidate = module.import_server_webdav_config(str(env), host)
                if not ok:
                    raise RuntimeError('Cannot inspect WebDAV configuration')
                candidates.append(candidate)
            if not candidates:
                raise RuntimeError('Cannot determine local server address')
            if not active():
                raise RuntimeError('WebDAV failed to start')
            verify_process(candidates[0]['enc'])
            return synchronize(cfg['database']['path'], candidates, module, backup)
        count = apply_change(env, args.set, restart, sync)
        print(f'WebDAV encryption applied; catalog records updated: {count}; backup: {backup}')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Exceptions may contain request URLs or configuration values: no secrets.
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print(f'WebDAV encryption operation failed: {detail}. Check service state and backup.', file=sys.stderr)
        sys.exit(1)
