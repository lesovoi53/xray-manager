"""Real service smoke checks; execute ONLY inside the disposable Debian lab."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import time
import urllib.request

assert Path('/.x-manager-test-lab').exists(), 'Disposable lab only'


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def envfile(path):
    data = {}
    for line in Path(path).read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            values = shlex.split(value)
            data[key] = values[0] if values else ''
    return data


def check_webdav():
    env = envfile('/etc/webdav-tunnel/config.env')
    port = int(env.get('WEBDAV_LISTEN', '').rsplit(':', 1)[-1] or env['SELFHOSTED_PORT'])
    assert port not in (443, 8443)
    password = env.get('SELFHOSTED_PASSWORD') or env['WEBDAV_PASSWORD']
    login = env.get('SELFHOSTED_LOGIN', 'wdav')
    authorization = base64.b64encode((login + ':' + password).encode()).decode()
    request = urllib.request.Request('http://127.0.0.1:%s/' % port, method='PROPFIND',
                                     headers={'Authorization': 'Basic ' + authorization, 'Depth': '0'})
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 207
    print('WebDAV PROPFIND: HTTP 207 (credentials not logged)')


for service in ('snell', 'mita', 'webdav-tunnel', 'tuna-subscriptions'):
    assert run('systemctl', 'is-active', service) == 'active', service
    assert run('systemctl', 'show', '--value', '-p', 'NRestarts', service) == '0', service
    print(service + ': active, no restart loop')
with urllib.request.urlopen('http://127.0.0.1:22217/api/users', timeout=5) as response:
    assert response.status == 200
print('Subscription API: HTTP 200')
check_webdav()
listeners = run('ss', '-H', '-lntup')
for line in listeners.splitlines():
    assert line.split()[4].rsplit(':', 1)[-1] not in ('443', '8443'), 'Forbidden listener'
print('Forbidden ports: no listeners on 443 or 8443')

# Reproduce the originally failing multi-mode as the real unprivileged service.
path = Path('/etc/webdav-tunnel/config.env')
before = path.read_bytes()
try:
    config = before.decode().replace('WEBDAV_MODE="selfhosted"', 'WEBDAV_MODE="multi"')
    config += '\nMULTI_LOCAL_ENABLED="true"\nMULTI_MAILRU_ENABLED="false"\n'
    path.write_text(config)
    subprocess.run(['systemctl', 'restart', 'webdav-tunnel'], check=True)
    time.sleep(4)
    assert run('systemctl', 'is-active', 'webdav-tunnel') == 'active'
    check_webdav()
    yaml = Path('/etc/webdav-tunnel/webdav-tunnel.yaml')
    assert yaml.exists() and yaml.stat().st_mode & 0o007 == 0
    print('WebDAV multi: active as wdavtunnel; generated YAML is private')
finally:
    path.write_bytes(before)
    subprocess.run(['systemctl', 'restart', 'webdav-tunnel'], check=True)
