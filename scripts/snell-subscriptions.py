#!/usr/bin/env python3
"""One Snell URI generator and explicit local-link synchronization.

Manual/external links are never discovered or enrolled by a background sync.
Database updates and binding changes share one SQLite transaction. Credentials
stay in files/stdin; diagnostics never include URIs, config values or tokens.
"""
import argparse
import configparser
from contextlib import closing
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit


class Error(Exception):
    pass


def settings(path, tag_path):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(path.read_text())
    section = parser['snell-server']
    host, port = section['listen'].rsplit(':', 1)
    value = dict(port=int(port), psk=section['psk'].strip(),
                 obfs=section.get('obfs', 'off').strip(),
                 obfs_host=section.get('obfs-host', '').strip(),
                 name=tag_path.read_text().strip() if tag_path.exists() else 'Snell-v5')
    if not value['psk'] or not 1 <= value['port'] <= 65535:
        raise Error('Invalid Snell key or port')
    if value['obfs'] not in ('off', 'none', 'http', 'tls'):
        raise Error('Unsupported Snell obfuscation')
    if value['obfs'] in ('http', 'tls') and not value['obfs_host']:
        raise Error('Missing obfuscation host')
    value['name'] = value['name'] or 'Snell-v5'
    if any(ord(c) < 32 for key in ('psk', 'name', 'obfs_host') for c in value[key]):
        raise Error('Invalid control character in Snell configuration')
    return value


def uri(value, host, previous=None, follow_name=True, previous_host=None):
    """Preserve per-link flags and names unless the name follows the service."""
    if not host or any(c.isspace() or c in '/?#@' for c in host):
        raise Error('Invalid server address')
    version = value.get('version', 5)
    if type(version) is not int or version not in (5, 6):
        raise Error('Unsupported Snell link version')
    if version == 5 and 'mode' in value:
        raise Error('Snell mode requires version 6')
    parsed = urlsplit(previous) if previous else None
    query = parse_qsl(parsed.query, keep_blank_values=True) if parsed else [
        ('version', str(version)), ('reuse', 'true'), ('tfo', 'true')]
    if version == 6:
        mode = value.get('mode', 'default')
        if mode not in ('default', 'unshaped', 'unsafe-raw'):
            raise Error('Unsupported Snell v6 mode')
        if value.get('obfs', 'off') not in ('off', 'none') or value.get('obfs_host'):
            raise Error('Snell v6 cannot use legacy obfuscation')
        if (type(value['port']) is not int or not 1 <= value['port'] <= 65535 or
                not value['psk'] or not value['name'] or
                any(ord(c) < 32 for key in ('psk', 'name') for c in value[key])):
            raise Error('Invalid Snell v6 identity')
        options = dict(query)
        if len(options) != len(query):
            raise Error('Duplicate Snell v6 query parameter')
        if (options.get('version') != '6' or (parsed and parsed.scheme != 'snell') or
                any(k in options for k in ('obfs-mode', 'obfs-host', 'obfs'))):
            raise Error('Incompatible previous Snell link; migration must be explicit')
        if set(options) - {'version', 'mode', 'reuse', 'tfo', 'network', 'udp-relay', 'userkey', 'quic-proxy-mode', 'quic_proxy_mode'}:
            raise Error('Unknown Snell v6 query parameter')
        if options.get('mode', 'default') not in ('default', 'unshaped', 'unsafe-raw'):
            raise Error('Invalid previous Snell v6 mode')
        for flag in ('reuse', 'tfo', 'udp-relay', 'quic-proxy-mode', 'quic_proxy_mode'):
            if flag in options and options[flag] not in ('true', 'false'):
                raise Error('Invalid Snell v6 boolean option')
        if any(options.get(k) == 'true' for k in ('quic-proxy-mode', 'quic_proxy_mode')):
            raise Error('QUIC Proxy is not supported by the selected Snell v6 server')
        if options.get('network', 'auto') not in ('auto', 'tcp', 'udp') or (options.get('network') == 'udp' and options.get('udp-relay') == 'false'):
            raise Error('Conflicting Snell v6 network options')
        if not parsed:
            query.append(('udp-relay', 'true'))
        query = [(k, v) for k, v in query if k != 'mode'] + [('mode', mode)]
    query = [(k, v) for k, v in query if k not in ('obfs-mode', 'obfs-host')]
    if version == 5:
        query = [(k, '4' if k == 'version' else v) for k, v in query]
    if version == 5 and value['obfs'] in ('http', 'tls'):
        query += [('obfs-mode', value['obfs']), ('obfs-host', value['obfs_host'])]
    # Only an explicit endpoint-address change migrates matching bound hosts.
    # Per-link address overrides and ordinary key/name updates retain their host.
    if parsed and (previous_host is None or parsed.hostname != previous_host.strip('[]').lower()):
        host = parsed.hostname
    host = host.strip('[]')
    authority = '[' + host + ']' if ':' in host else host
    authority = quote(value['psk'], safe='') + '@' + authority + ':' + str(value['port'])
    name = quote(value['name'], safe='') if follow_name or not parsed else parsed.fragment
    return urlunsplit(('snell', authority, parsed.path if parsed else '/', urlencode(query), name))


def matches(link, value, host):
    try:
        p = urlsplit(link)
        return (p.scheme == 'snell' and p.hostname == host.strip('[]') and
                p.port == value['port'] and unquote(p.username or '') == value['psk'] and
                dict(parse_qsl(p.query)).get('version', '5') in ('4', '5'))
    except ValueError:
        return False


def synchronize(db, value, host, bind_user=None, adopt=False, endpoint_id=None, previous_host=None):
    """Caller owns transaction. Only exact, explicitly bound URI snapshots move."""
    version = value.get('version', 5)
    uri(value, host)  # Validate before writing bindings or subscription data.
    table = 'x_manager_snell_links'
    scope, scope_args = '', ()
    extra_column, extra_placeholder = '', ''
    if version == 6:
        if not isinstance(endpoint_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', endpoint_id):
            raise Error('Snell v6 requires a stable explicit endpoint ID')
        if adopt:
            raise Error('Snell v6 adoption is not supported; bind the exact generated link')
        table = 'x_manager_snell_endpoint_links'
        scope, scope_args = 'endpoint_id=? AND ', (endpoint_id,)
        extra_column, extra_placeholder = 'endpoint_id TEXT NOT NULL, ', '?, '
    db.execute(f'''CREATE TABLE IF NOT EXISTS {table} (
        {extra_column}
        user_id TEXT NOT NULL, uri TEXT NOT NULL, follow_name INTEGER NOT NULL,
        PRIMARY KEY({'endpoint_id, ' if version == 6 else ''}user_id, uri))''')
    if bind_user:
        row = db.execute('SELECT snell_uri FROM users WHERE id=?', (bind_user,)).fetchone()
        if row is None:
            raise Error('Subscription user not found')
        candidates = [s for s in (row[0] or '').splitlines() if
                      (matches(s, value, host) if adopt else s == uri(value, host))]
        if len(candidates) != 1:
            raise Error('Expected one unambiguous local Snell link; no changes made')
        link = candidates[0]
        if version == 6 and db.execute(
                f'SELECT 1 FROM {table} WHERE user_id=? AND uri=? AND endpoint_id<>?',
                (bind_user, link, endpoint_id)).fetchone():
            raise Error('Snell link is already bound to another endpoint')
        follow = unquote(urlsplit(link).fragment) in (value['name'], 'Snell-v' + str(version), '')
        db.execute(f'INSERT OR IGNORE INTO {table} VALUES ({extra_placeholder}?,?,?)',
                   (*scope_args, bind_user, link, int(follow)))
    changed = 0
    groups_exist = db.execute("SELECT 1 FROM sqlite_master WHERE name='user_connection_groups'").fetchone()
    for user in db.execute('SELECT id,snell_uri FROM users').fetchall():
        uid, raw = user
        lines = (raw or '').splitlines()
        replacements = {}
        bindings = db.execute(f'SELECT uri,follow_name FROM {table} WHERE {scope}user_id=?', (*scope_args, uid)).fetchall()
        document = None
        if groups_exist and bindings:
            row = db.execute('SELECT document_json FROM user_connection_groups WHERE user_id=?', (uid,)).fetchone()
            if row:
                document = json.loads(row[0])
        group_uris = {profile['uri'] for profile in document['profiles']} if document else set()
        for old, follow in bindings:
            if old not in lines and old not in group_uris:
                # Detach only once no exact snapshot remains in either delivery.
                db.execute(f'DELETE FROM {table} WHERE {scope}user_id=? AND uri=?', (*scope_args, uid, old))
                continue
            new = uri(value, host, old, bool(follow), previous_host=previous_host)
            if new != old:
                replacements[old] = new
        if not replacements:
            continue
        updated = [replacements.get(line, line) for line in lines]
        if len(set(updated)) != len(set(lines)):
            raise Error('Synchronization would duplicate a Snell link')
        if document:
            touched = False
            for profile in document['profiles']:
                if profile['uri'] in replacements:
                    profile['uri'] = replacements[profile['uri']]
                    touched = True
            if touched:
                if len({p['uri'] for p in document['profiles']}) != len(document['profiles']):
                    raise Error('Synchronization would duplicate a group profile')
                db.execute('UPDATE user_connection_groups SET document_json=? WHERE user_id=?',
                           (json.dumps(document, ensure_ascii=False), uid))
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.execute('UPDATE users SET snell_uri=?, revision=revision+1, updated_at=? WHERE id=?',
                   ('\n'.join(updated), now, uid))
        for old, new in replacements.items():
            db.execute(f'UPDATE {table} SET uri=? WHERE {scope}user_id=? AND uri=?', (new, *scope_args, uid, old))
        changed += 1
    db.execute(f'DELETE FROM {table} WHERE {scope}user_id NOT IN (SELECT id FROM users)', scope_args)
    return changed


def atomic_write(path, data):
    stat = path.stat() if path.exists() else None
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            if stat:
                os.fchown(stream.fileno(), stat.st_uid, stat.st_gid)
                os.fchmod(stream.fileno(), stat.st_mode & 0o777)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def edit_config(data, changes):
    text = data.decode()
    # Limit edits to the server section, preserving unrelated options/comments.
    match = re.search(r'(?ms)^\[snell-server\][^\n]*\n(.*?)(?=^\[|\Z)', text)
    if not match:
        raise Error('Missing Snell server section')
    body = match.group(1)
    for key, value in changes.items():
        body = re.sub(r'(?m)^\s*' + re.escape(key) + r'\s*=.*\n?', '', body)
        if value is not None:
            body = body.rstrip('\n') + '\n' + key + ' = ' + value + '\n'
    return (text[:match.start(1)] + body + text[match.end(1):]).encode()


def run(*args, **kwargs):
    p = subprocess.run(args, capture_output=True, **kwargs)
    if p.returncode:
        raise Error('Command failed: ' + args[0] + ' ' + args[1])
    return p.stdout


def restart():
    run('systemctl', 'restart', 'snell')
    time.sleep(2)
    run('systemctl', 'is-active', '--quiet', 'snell')


def port_rules(old_port, new_port):
    """Move only known Snell INPUT rules, retaining blocked/open policy."""
    rules = run('iptables', '-w', '-S', 'INPUT').decode().splitlines()
    position = 0
    for line in rules:
        rule = shlex.split(line)
        if rule[:2] != ['-A', 'INPUT']:
            continue
        position += 1
        if '--dport' not in rule or rule[rule.index('--dport') + 1] != str(old_port):
            continue
        if '-p' not in rule or rule[rule.index('-p') + 1] not in ('tcp', 'udp'):
            continue
        recognized = ('SNELL_MANAGED' in rule or 'SNELL_FW_BLOCK' in rule or
                      re.fullmatch(r'-A INPUT -p (tcp|udp)( -m (tcp|udp))? --dport \d+ -j ACCEPT', line))
        if recognized:
            new = rule[2:]
            new[new.index('--dport') + 1] = str(new_port)
            run('iptables', '-w', '-R', 'INPUT', str(position), *new)


def transaction(config, tag, db_path, host, backup_root, change=None, bind_user=None, adopt=False,
                restart_service=restart):
    before = settings(config, tag)
    after = dict(before)
    config_bytes, tag_bytes = config.read_bytes(), tag.read_bytes() if tag.exists() else None
    new_config, new_tag = config_bytes, tag_bytes
    change = change or {}
    if set(change) - {'name', 'psk', 'port', 'obfs', 'obfs_host'}:
        raise Error('Unknown Snell setting')
    after.update(change)
    for field in ('name', 'psk', 'obfs_host'):
        if not isinstance(after[field], str) or any(ord(c) < 32 for c in after[field]):
            raise Error('Invalid Snell setting')
    if not after['name'].strip() or not after['psk'].strip():
        raise Error('Empty Snell name or key')
    if after['obfs'] not in ('off', 'none', 'http', 'tls'):
        raise Error('Unsupported obfuscation')
    if after['obfs'] in ('http', 'tls') and not re.fullmatch(r'[A-Za-z0-9.-]+', after['obfs_host']):
        raise Error('Invalid obfuscation domain')
    if type(after['port']) is not int or not 1 <= after['port'] <= 65535:
        raise Error('Invalid port')
    port_changed = after['port'] != before['port']
    if port_changed and after['port'] in (443, 8443):
        raise Error('Ports 443 and 8443 are forbidden')
    if port_changed:
        sockets = []
        try:
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(socket.AF_INET, kind)
                sockets.append(sock)
                sock.bind(('0.0.0.0', after['port']))
        except OSError:
            raise Error('Requested port is occupied') from None
        finally:
            for sock in sockets:
                sock.close()
    edits = {}
    if 'obfs' in change or 'obfs_host' in change:
        edits.update({'obfs': after['obfs'], 'obfs-host': after['obfs_host'] if after['obfs'] in ('http', 'tls') else None})
    if 'psk' in change:
        edits['psk'] = after['psk']
    if port_changed:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(config_bytes.decode())
        edits['listen'] = parser['snell-server']['listen'].rsplit(':', 1)[0] + ':' + str(after['port'])
    if edits:
        new_config = edit_config(config_bytes, edits)
    if 'name' in change:
        after['name'] = after['name'].strip()
        new_tag = (after['name'] + '\n').encode()
    needs_restart = new_config != config_bytes
    if needs_restart:
        run('systemctl', 'is-active', '--quiet', 'snell')
    backup = Path(tempfile.mkdtemp(prefix='x-manager-snell-', dir=backup_root))
    (backup / 'snell-server.conf').write_bytes(config_bytes)
    if tag_bytes is not None:
        (backup / 'tag.txt').write_bytes(tag_bytes)
    firewall = run('iptables-save') if port_changed else None
    if firewall is not None:
        (backup / 'iptables.rules').write_bytes(firewall)
    db = None
    files_changed = False
    try:
        if db_path:
            db = sqlite3.connect(Path(db_path).as_uri() + '?mode=rw', uri=True, timeout=15)
            with closing(sqlite3.connect(backup / 'subscriptions.db')) as dest:
                db.backup(dest)
            db.execute('BEGIN IMMEDIATE')
            count = synchronize(db, after, host, bind_user, adopt)
        else:
            if bind_user:
                raise Error('TUNA database not configured')
            count = 0
        if new_config != config_bytes or new_tag != tag_bytes:
            files_changed = True
            if new_config != config_bytes:
                atomic_write(config, new_config)
            if new_tag != tag_bytes:
                atomic_write(tag, new_tag)
            if port_changed:
                port_rules(before['port'], after['port'])
            if needs_restart:
                restart_service()
        # No fallible filesystem work after commit: otherwise an I/O failure
        # could restore config after the database has already committed.
        (backup / 'result.json').write_text(json.dumps({'users_updated': count,
                                                       'tag_existed': tag_bytes is not None}))
        if db:
            db.commit()
        return count, backup
    except Exception:
        if db:
            db.rollback()
        try:
            if files_changed:
                atomic_write(config, config_bytes)
                if tag_bytes is None:
                    tag.unlink(missing_ok=True)
                else:
                    atomic_write(tag, tag_bytes)
                if firewall is not None:
                    run('iptables-restore', input=firewall)
                if needs_restart:
                    restart_service()
        except Exception:
            raise Error('Rollback incomplete; inspect backup: ' + str(backup)) from None
        raise
    finally:
        if db:
            db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('uri', 'sync', 'bind', 'adopt', 'set'))
    parser.add_argument('--server-ip', required=True)
    parser.add_argument('--user')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise Error('Run as root')
    config, tag = Path('/etc/snell/snell-server.conf'), Path('/etc/snell/tag.txt')
    if args.action == 'uri':
        print(uri(settings(config, tag), args.server_ip))
        return
    if args.action in ('bind', 'adopt') and not args.user:
        raise Error('Explicit user ID is required')
    os.umask(0o077)
    db_path = None
    tuna_cfg = Path('/etc/tuna-subscriptions/config.toml')
    if tuna_cfg.exists():
        cfg = tomllib.loads(tuna_cfg.read_text())
        db_path = Path(cfg['database']['path'])
        if not db_path.is_absolute():
            db_path = Path('/var/lib/tuna-subscriptions') / db_path
        if not db_path.is_file():
            raise Error('Configured TUNA database is missing')
    change = json.load(sys.stdin) if args.action == 'set' else None
    with open('/run/lock/x-manager-snell.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        count, backup = transaction(config, tag, db_path, args.server_ip, '/var/backups', change,
                                    args.user if args.action in ('bind', 'adopt') else None,
                                    args.action == 'adopt')
    print('Snell: users updated: ' + str(count) + '; backup: ' + str(backup))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = str(error) if isinstance(error, Error) else type(error).__name__
        print('Snell operation failed: ' + message, file=sys.stderr)
        sys.exit(1)
