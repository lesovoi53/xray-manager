"""Real Snell/systemd/HTTP acceptance in the disposable Debian lab only."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import urllib.request
from urllib.parse import parse_qs, urlsplit, unquote

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab only'
helper = '/usr/local/share/x-manager/scripts/snell-subscriptions.py'
config = Path('/etc/snell/snell-server.conf')
tag = Path('/etc/snell/tag.txt')
host = '127.0.0.1'


def run(*args, **kw):
    p = subprocess.run(args, capture_output=True, **kw)
    assert p.returncode == 0, 'Command failed: '+args[0]
    return p.stdout.decode().strip()


def tool(action, change=None, user=None):
    args = ['python3', helper, action, '--server-ip',host]
    if user:
        args += ['--user',user]
    return run(*args,input=json.dumps(change).encode() if change else None)


run('systemctl','enable','--now','snell')
link = tool('uri')
request = urllib.request.Request('http://127.0.0.1:22217/api/users',
    data=json.dumps({'nickname':'snell-fixture-'+os.urandom(3).hex(),'snell_uri':link}).encode(),
    headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request) as response:
    user = json.load(response)
uid, token = user['id'], user['token']
tool('bind',user=uid)


def subscription():
    with urllib.request.urlopen('http://127.0.0.1:22217/sub/'+token) as response:
        assert response.status == 200
        links = base64.b64decode(response.read()).decode().splitlines()
        return next(s for s in links if s.startswith('snell://')),response.headers['ETag']


tool('set',{'obfs':'http','obfs_host':'yandex.ru','name':'Local name & пробел'})
p = urlsplit(subscription()[0])
assert parse_qs(p.query)['obfs-mode'] == ['http']
assert parse_qs(p.query)['obfs-host'] == ['yandex.ru']
assert unquote(p.fragment) == 'Local name & пробел'
assert subscription()[0] == tool('uri')
before = subscription()
tool('sync')
assert subscription() == before, 'Repeat synchronization changed ETag or URI'
print('PASS real Snell HTTP obfuscation + TUNA HTTP 200 + repeat/ETag',flush=True)

spec = importlib.util.spec_from_file_location('snell_fixture', helper)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
original = config.read_bytes()
override = Path('/etc/systemd/system/snell.service.d/99-snell-test-failure.conf')
assert not override.exists()
override.parent.mkdir(exist_ok=True)
calls = []


def fail_once():
    calls.append(1)
    if len(calls) > 1:
        module.restart()
        return
    override.write_text('[Service]\nExecStart=\nExecStart=/bin/false\nRestart=no\n')
    try:
        run('systemctl','daemon-reload')
        module.restart()
    finally:
        override.unlink()
        run('systemctl','daemon-reload')


try:
    module.transaction(config,tag,Path('/var/lib/tuna-subscriptions/subscriptions.db'),host,
                       '/var/backups',{'obfs':'off'},restart_service=fail_once)
except module.Error:
    pass
else:
    raise AssertionError('Synthetic systemd failure was hidden')
assert len(calls)==2
assert config.read_bytes()==original
assert subscription()==before
run('systemctl','is-active','--quiet','snell')
print('PASS actual systemd failure, config/database rollback and service recovery',flush=True)
tool('set',{'obfs':'off'})
assert 'obfs-mode' not in parse_qs(urlsplit(subscription()[0]).query)
before = subscription()
with sqlite3.connect('/var/lib/tuna-subscriptions/subscriptions.db') as db:
    before_user = db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
config_hash = hashlib.sha256(config.read_bytes()).digest()
with open('/tmp/snell-install-repeat.log','wb') as log:
    result = subprocess.run(['bash','/work/x-manager/install.sh','--update'],
                            env=dict(os.environ,XM_COMPONENT_DIR='/opt/xm-assets'),stdout=log,stderr=subprocess.STDOUT)
assert result.returncode == 0, 'Installer repeat failed; inspect private log'
with sqlite3.connect('/var/lib/tuna-subscriptions/subscriptions.db') as db:
    assert db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()==before_user
    assert db.execute('SELECT COUNT(*) FROM x_manager_snell_links WHERE user_id=?',(uid,)).fetchone()[0]==1
assert hashlib.sha256(config.read_bytes()).digest()==config_hash
assert subscription()==before
print('PASS off + repeat installer preserves config, token, user revision, binding and HTTP body',flush=True)
