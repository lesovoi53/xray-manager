#!/usr/bin/env python3
"""Export from the running Mita RPC snapshot; explicitly repair one saved URI.

Never discover/adopt local links by IP. Repair requires the exact URI SHA256,
user ID, revision, matching credentials, port binding and original pattern.
No bulk synchronization or service/configuration mutations.
"""
import argparse
from contextlib import closing
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit


class Error(Exception):
    pass


def mita(*args):
    result = subprocess.run(['mita', *args], capture_output=True, text=True, timeout=20)
    if result.returncode:
        # Mita diagnostics may contain configuration values/credentials.
        raise Error('Mita RPC/codec failed; verify the running service and installed version')
    return result.stdout.strip()


def decode(payload):
    return json.loads(mita('explain', 'traffic-pattern', payload)) if payload else {}


def entropy(pattern):
    low = pattern.get('lowEntropy', {})
    result = {}
    for field, query, expression in (
        ('mode', 'low-entropy-mode', r'LOW_ENTROPY_MODE_(OFF|32|40|48|56)'),
        ('maskRotation', 'low-entropy-mask-rotation', r'LOW_ENTROPY_MASK_(NO_ROTATION|ROTATE_(LEFT|RIGHT)_([1-9]|1[0-5]))'),
    ):
        if field in low:
            if not isinstance(low[field], str) or not re.fullmatch(expression, low[field]):
                raise Error('Unknown traffic-pattern low entropy enum')
            result[query] = low[field]
    return result


def snapshot():
    before = json.loads(mita('describe', 'config'))
    payload = mita('export', 'traffic-pattern')
    original = decode(payload)
    effective = json.loads(mita('describe', 'effective-traffic-pattern'))
    after = json.loads(mita('describe', 'config'))
    if before != after or original != before.get('trafficPattern', {}):
        raise Error('Mita configuration changed during export; retry')
    values = entropy(effective)
    if any(values.get(k) != v for k, v in entropy(original).items()):
        raise Error('Original and effective traffic patterns disagree; refusing export')
    if len(values) != 2:
        raise Error('Mita did not supply the effective low entropy settings')
    return dict(config=before, payload=payload, original=original, entropy=values)


def binding(item):
    ports = str(item.get('portRange') or item.get('port') or '')
    protocol = item.get('protocol')
    if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', ports) or protocol not in ('TCP', 'UDP'):
        raise Error('Invalid Mita port binding')
    nums = [int(p) for p in ports.split('-')]
    if not all(1 <= p <= 65535 for p in nums) or nums[0] > nums[-1]:
        raise Error('Invalid Mita port range')
    return ports, protocol


def export(model, host, username, name):
    if not host or any(c.isspace() or c in '/?#@' for c in host):
        raise Error('Invalid server address')
    users = [u for u in model['config'].get('users', []) if u.get('name') == username]
    if len(users) != 1 or not users[0].get('password'):
        raise Error('Selected user has no exportable password in the running Mita configuration')
    bindings = model['config'].get('portBindings', [])
    if not bindings:
        raise Error('Mita has no port bindings')
    ports, protocol = binding(bindings[0])
    params = dict(profile=name, port=ports, protocol=protocol, multiplexing='MULTIPLEXING_HIGH')
    params['traffic-pattern'] = model['payload']
    params.update(model['entropy'])
    address = '[' + host.strip('[]') + ']' if ':' in host else host
    password = users[0]['password']
    uri = 'mierus://' + quote(username, safe='') + ':' + quote(password, safe='') + '@' + address + '/?' + urlencode(params)
    return dict(uri=uri, pattern=model['payload'], port=ports, protocol=protocol,
                username=username, password=password, **model['entropy'])


def parse(uri):
    p = urlsplit(uri)
    if p.scheme != 'mierus' or not p.hostname or p.username is None or p.password is None:
        raise Error('Invalid Mieru URI')
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if len(dict(pairs)) != len(pairs):
        raise Error('Duplicate Mieru query parameters')
    return p, dict(pairs)


def validate(uri):
    _, params = parse(uri)
    entropy({'lowEntropy': {field: params[key] for field, key in
             (('mode','low-entropy-mode'),('maskRotation','low-entropy-mask-rotation')) if key in params}})
    declared = entropy(decode(params.get('traffic-pattern', '')))
    for key, value in declared.items():
        if key in params and params[key] != value:
            raise Error('Conflicting Mieru low entropy settings')
    return params


def repaired(uri, model, host):
    parsed, params = parse(uri)
    if parsed.hostname != host.strip('[]') or parsed.port is not None:
        raise Error('Selected URI does not match the explicit local endpoint')
    users = model['config'].get('users', [])
    if not any(u.get('name') == unquote(parsed.username) and u.get('password') == unquote(parsed.password) for u in users):
        raise Error('Selected URI does not match the running Mita credentials')
    if (params.get('port'), params.get('protocol')) not in [binding(b) for b in model['config'].get('portBindings', [])]:
        raise Error('Selected URI does not match the running Mita port binding')
    if 'traffic-pattern' not in params or decode(params['traffic-pattern']) != model['original']:
        raise Error('Selected URI pattern differs from the running service; refusing a guessed repair')
    # Keep every other byte, including name, credentials, encoded pattern and
    # unknown client options. Only the two redundant enum fields are corrected.
    updated, seen = [], set()
    for part in parsed.query.split('&'):
        key = unquote(part.split('=', 1)[0])
        if key in model['entropy']:
            part = key + '=' + quote(model['entropy'][key], safe='')
            seen.add(key)
        updated.append(part)
    updated += [k + '=' + quote(v, safe='') for k, v in model['entropy'].items() if k not in seen]
    result = urlunsplit(parsed._replace(query='&'.join(updated)))
    validate(result)
    return result


def repair(db_path, request, model, host, apply=False, backup_root=Path('/var/backups')):
    with closing(sqlite3.connect('file:' + str(db_path) + '?mode=rw', uri=True, timeout=15)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN IMMEDIATE')
        try:
            row = db.execute('SELECT mieru_uri, revision FROM users WHERE id=?', (request['user_id'],)).fetchone()
            if row is None or row['revision'] != request['revision']:
                raise Error('User revision changed or user missing')
            old = row['mieru_uri'] or ''
            lines = old.splitlines(keepends=True)
            targets = [i for i, line in enumerate(lines) if hashlib.sha256(line.strip().encode()).hexdigest() == request['uri_sha256']]
            if len(targets) != 1:
                raise Error('Expected exactly one explicitly selected URI')
            index = targets[0]
            previous = lines[index].strip()
            new = repaired(previous, model, host)
            result = dict(changed=new != previous, revision=row['revision'], applied=False,
                          entropy=model['entropy'], backup=None)
            if not apply or new == previous:
                db.rollback()
                return result
            backup = Path(tempfile.mkdtemp(prefix='x-manager-mieru-', dir=backup_root))
            backup.chmod(0o700)
            # Backup from another reader while the writer reservation excludes
            # concurrent updates. Includes committed WAL, without self-deadlock.
            with closing(sqlite3.connect('file:' + str(db_path) + '?mode=ro', uri=True)) as src:
                with closing(sqlite3.connect(backup / 'subscriptions.db')) as dst:
                    src.backup(dst)
            lines[index] = lines[index].replace(previous, new, 1)
            if sum(line.strip() == new for line in lines) != 1:
                raise Error('Repair would duplicate a saved URI')
            db.execute('UPDATE users SET mieru_uri=?, revision=revision+1, updated_at=? WHERE id=?',
                       (''.join(lines), datetime.datetime.now(datetime.timezone.utc).isoformat(), request['user_id']))
            group_before = group_after = None
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='user_connection_groups'").fetchone():
                group = db.execute('SELECT document_json FROM user_connection_groups WHERE user_id=?', (request['user_id'],)).fetchone()
                if group:
                    document = json.loads(group[0])
                    touched = False
                    for profile in document.get('profiles', []):
                        if profile.get('uri') == previous:
                            profile['uri'] = new
                            touched = True
                    if touched:
                        if len({p['uri'] for p in document['profiles']}) != len(document['profiles']):
                            raise Error('Repair would duplicate a group profile')
                        group_before, group_after = group[0], json.dumps(document, ensure_ascii=False)
                        db.execute('UPDATE user_connection_groups SET document_json=? WHERE user_id=?',
                                   (group_after, request['user_id']))
            (backup/'change.json').write_text(json.dumps(dict(user_id=request['user_id'],
                revision_after=row['revision']+1,before=old,after=''.join(lines),
                group_before=group_before,group_after=group_after)))
            db.commit()
            return dict(result, applied=True, revision=row['revision'] + 1, backup=str(backup))
        except Exception:
            db.rollback()
            raise


def restore(db_path, backup):
    change=json.loads((backup/'change.json').read_text())
    with closing(sqlite3.connect('file:'+str(db_path)+'?mode=rw',uri=True,timeout=15)) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            current=db.execute('SELECT mieru_uri,revision FROM users WHERE id=?',(change['user_id'],)).fetchone()
            if current != (change['after'],change['revision_after']):
                raise Error('User changed since repair; refusing to overwrite newer data')
            if change['group_after'] is not None:
                current=db.execute('SELECT document_json FROM user_connection_groups WHERE user_id=?',(change['user_id'],)).fetchone()
                if current != (change['group_after'],):
                    raise Error('Groups changed since repair; refusing rollback')
                db.execute('UPDATE user_connection_groups SET document_json=? WHERE user_id=?',
                           (change['group_before'],change['user_id']))
            db.execute('UPDATE users SET mieru_uri=?,revision=revision+1,updated_at=? WHERE id=?',
                       (change['before'],datetime.datetime.now(datetime.timezone.utc).isoformat(),change['user_id']))
            db.commit()
            return dict(restored=True,revision=change['revision_after']+1)
        except Exception:
            db.rollback()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['export', 'preview', 'repair', 'restore', 'validate'])
    parser.add_argument('--server-ip')
    parser.add_argument('--user')
    parser.add_argument('--name', default='Mieru-Home')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--database', type=Path)
    parser.add_argument('--backup', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.action == 'restore':
        if not args.database or not args.backup:
            raise Error('Explicit database and repair backup required')
        print(json.dumps(restore(args.database,args.backup)))
        return
    if args.action == 'validate':
        validate(sys.stdin.read().strip())
        print('Mieru URI is consistent')
        return
    model = snapshot()
    if args.action == 'export':
        result = export(model, args.server_ip, args.user, args.name)
        print(json.dumps(result, ensure_ascii=False) if args.json else result['uri'])
    else:
        if not args.database or not args.server_ip:
            raise Error('Explicit database path and local server address required')
        print(json.dumps(repair(args.database, json.load(sys.stdin), model, args.server_ip,
                                apply=args.action == 'repair')))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('Mieru export/repair failed: ' + (str(exc) if isinstance(exc, Error) else type(exc).__name__), file=sys.stderr)
        sys.exit(1)
