"""The printed rollback command must work after the updater removes its temp dir."""
import os
from pathlib import Path
import re
import subprocess

assert Path('/.x-manager-test-lab').exists(), 'Disposable lab only'
env=dict(os.environ, XM_COMPONENT_DIR='/opt/xm-assets')
log=Path('/tmp/xm-persistent-distribution.log')
with log.open('w') as out:
    result=subprocess.run(['bash','/work/x-manager/install.sh','--update'],env=env,stdout=out,stderr=subprocess.STDOUT)
assert result.returncode==0, 'Update failed; inspect the private log'
command=re.search(r'^Rollback: (.+)$',log.read_text(),re.M).group(1)
assert '/usr/local/share/x-manager/distribution/install.sh' in command
assert Path('/usr/local/share/x-manager/distribution/scripts/menu-actions.tsv').is_file()
result=subprocess.run(['bash','-c',command],env=env,capture_output=True,text=True)
assert result.returncode==0, 'Printed rollback command failed'
print('PASS: complete persistent distribution installed; printed rollback command restores backup successfully')
