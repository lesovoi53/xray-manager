"""Clean/repeat acceptance, ONLY in the marked disposable systemd namespace."""
import json
import os
from pathlib import Path
import subprocess

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab only'
root = Path('/work/x-manager')
pristine = [p.parent for p in Path('/var/backups').glob('x-manager-*/state.json')
            if '/etc/snell' not in json.loads(p.read_text())['present']]
if pristine:
    backup = min(pristine, key=lambda p: p.stat().st_mtime)
    subprocess.run(['python3', str(backup/'installer-state.py'), 'restore', str(backup)], check=True)
else:
    assert not Path('/usr/local/bin/x-manager').exists(), 'No clean checkpoint; refusing removal'
env = dict(os.environ, XM_COMPONENT_DIR='/opt/xm-assets')
for mode in ('--direct', '--update'):
    with open('/tmp/x-manager-clean-release.log', 'w') as log:
        result = subprocess.run(['bash', str(root/'install.sh'), mode], env=env, stdout=log, stderr=subprocess.STDOUT)
    assert result.returncode == 0, 'Installation failed; inspect private /tmp/x-manager-clean-release.log'
    subprocess.run(['python3', str(root/'tests/lab-smoke.py')], check=True)
    print('PASS clean/repeat ' + mode, flush=True)
# A stopped service and disabled autostart must survive another update.
subprocess.run(['systemctl', 'stop', 'snell'], check=True)
subprocess.run(['systemctl', 'disable', 'snell'], check=True)
with open('/tmp/x-manager-stopped-service.log', 'w') as log:
    result = subprocess.run(['bash', str(root/'install.sh'), '--update'], env=env, stdout=log, stderr=subprocess.STDOUT)
assert result.returncode == 0
assert subprocess.run(['systemctl', 'is-active', '--quiet', 'snell']).returncode != 0
assert subprocess.run(['systemctl','is-enabled','snell'],text=True,capture_output=True).stdout.strip() == 'disabled'
print('PASS stopped/disabled service state preserved')
