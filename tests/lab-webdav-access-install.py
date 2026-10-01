"""Only run in the marked disposable systemd Debian lab."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

assert Path('/.x-manager-test-lab').is_file()
ROOT=Path('/work/x-manager')
helper='/usr/local/share/x-manager/scripts/webdav-access.py'
env=dict(os.environ,XM_COMPONENT_DIR='/opt/xm-assets')
config=Path('/etc/webdav-tunnel/config.env')
original=hashlib.sha256(config.read_bytes()).hexdigest()

def run(*args): return subprocess.check_output(args,text=True).strip()
def blocked():
    assert json.loads(Path('/etc/webdav-tunnel/access-policy.json').read_text())=={'state':'blocked'}
    for family in ('iptables','ip6tables'):
        rules=run(family,'-S','INPUT')
        matches=[line for line in rules.splitlines() if 'XM_WEBDAV_ACCESS' in line]
        assert len(matches)==1 and matches[0].endswith('-j DROP')
    assert run('systemctl','is-active','webdav-tunnel')=='active'

with open('/tmp/webdav-access-install.log','w') as log:
    subprocess.run(['bash',str(ROOT/'install.sh'),'--update'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
assert hashlib.sha256(config.read_bytes()).hexdigest()==original
run('python3',helper,'blocked')
run('systemctl','restart','webdav-tunnel')
blocked()
subprocess.run(['python3',str(ROOT/'tests/lab-persistent-rollback.py')],env=env,check=True)
blocked()
assert hashlib.sha256(config.read_bytes()).hexdigest()==original
run('python3',helper,'open')
for family in ('iptables','ip6tables'):
    assert next(line for line in run(family,'-S','INPUT').splitlines() if 'XM_WEBDAV_ACCESS' in line).endswith('-j ACCEPT')
subprocess.run(['python3',str(ROOT/'tests/lab-smoke.py')],check=True)
print('PASS systemd: upgrade installs helper, blocked policy survives restart/update/full rollback, open succeeds, config hash preserved, services and HTTP checked')
