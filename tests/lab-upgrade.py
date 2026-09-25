"""Seed/check a real upgrade without printing credentials or tokens."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import urllib.request

assert Path('/.x-manager-test-lab').exists(), 'Disposable lab only'
state_path = Path('/root/x-manager-upgrade-state.json')


def hashes():
    result = {}
    for directory in ('/etc/snell', '/etc/mita', '/etc/openflux', '/etc/webdav-tunnel', '/etc/x-manager', '/etc/tuna-subscriptions'):
        for file in Path(directory).rglob('*'):
            if file.is_file() and file.suffix not in ('.yaml', '.key'):
                result[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()
    return result


def users():
    with sqlite3.connect('/var/lib/tuna-subscriptions/subscriptions.db') as db:
        return [list(row) for row in db.execute('SELECT * FROM users ORDER BY id')]


if sys.argv[1] == 'seed':
    request = urllib.request.Request('http://127.0.0.1:22217/api/users',
                                     data=json.dumps({'nickname': 'upgrade-fixture', 'custom_uri': 'vless://11111111-2222-4333-8444-555555555555@192.0.2.1:24443?security=tls&x-preserved=yes#fixture'}).encode(),
                                     headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request) as response:
        created = json.load(response)
    Path('/etc/snell/tag.txt').write_text('Preserved custom name\n')
    config = Path('/etc/snell/snell-server.conf')
    config.write_text(config.read_text().replace(':1488', ':21488'))
    subprocess.run(['systemctl', 'restart', 'snell'], check=True)
    Path('/etc/openflux/instances/3.env').write_text('ROLE="exit"\nMODE="l4"\nTRANSPORT="boards"\nCODEC="batched"\nDEBUG="0"\nURL=""\nENCRYPTION_KEY="fixture-key-never-printed"\n')
    os.chown('/etc/webdav-tunnel', 0, 0)
    os.chmod('/etc/webdav-tunnel', 0o755)  # Simulate old installer permissions.
    with urllib.request.urlopen('http://127.0.0.1:22217/sub/' + created['token']) as response:
        legacy_hash = hashlib.sha256(response.read()).hexdigest()
    state_path.write_text(json.dumps(dict(hashes=hashes(), users=users(), token=created['token'], uid=created['id'], legacy=legacy_hash)))
    state_path.chmod(0o600)
    print('Seeded custom ports, names, OpenFlux codec/key and subscription user; no secrets logged')
else:
    expected = json.loads(state_path.read_text())
    assert hashes() == expected['hashes'], 'Configuration content changed during upgrade'
    assert users() == expected['users'], 'Existing users/tokens/revisions changed during upgrade'
    with urllib.request.urlopen('http://127.0.0.1:22217/sub/' + expected['token']) as response:
        assert hashlib.sha256(response.read()).hexdigest() == expected['legacy']
    for service in ('snell', 'mita', 'webdav-tunnel', 'tuna-subscriptions'):
        subprocess.run(['systemctl', 'is-active', '--quiet', service], check=True)
    rules = subprocess.check_output(['iptables-save'], text=True)
    entries = [line for line in rules.splitlines() if line.startswith('-A ')]
    assert len(entries) == len(set(entries)), 'Duplicate firewall rules'
    print('PASS: configuration hashes, users, tokens, ports, codecs, keys and legacy subscription preserved; services active; no duplicate firewall rules')
