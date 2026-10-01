"""Real installer update/rollback with live Xray and active Snell TPROXY policy."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab only'
ROOT=Path('/work/x-manager')
spec=importlib.util.spec_from_file_location('state',ROOT/'scripts/installer-state.py')
state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
assert Path('/etc/snell/routing.mode').read_text().strip()=='direct'
assert not state.snell_policy()['rules']
os.umask(0o077)
backup=Path(tempfile.mkdtemp(prefix='x-manager-policy-lab-',dir='/var/backups'))
state.snapshot(backup,ROOT/'tuna-sub-server/tuna-subscriptions.py')
with tempfile.TemporaryDirectory(prefix='snell-xray-') as tmp:
    temp=Path(tmp)
    ports={k:int(v) for line in Path('/etc/x-manager/gateways.env').read_text().splitlines() if '=' in line
           for k,v in [line.split('=',1)] if k.startswith('XRAY_') and v.isdigit()}
    inbounds=[dict(tag='socks',listen='127.0.0.1',port=ports['XRAY_SOCKS_PORT'],protocol='socks',settings=dict(auth='noauth',udp=True))]
    for mode,key in [('redirect','XRAY_REDIRECT_PORT'),('tproxy','XRAY_TPROXY_PORT')]:
        inbounds.append(dict(tag=mode,listen='127.0.0.1',port=ports[key],protocol='dokodemo-door',
            settings=dict(network='tcp,udp',followRedirect=True),streamSettings=dict(sockopt=dict(tproxy=mode))))
    config=temp/'config.json';config.write_text(json.dumps(dict(inbounds=inbounds,outbounds=[dict(protocol='freedom',tag='direct')])))
    env=dict(os.environ,XM_COMPONENT_DIR='/opt/xm-assets',XM_XRAY_CONFIG=str(config))
    with (temp/'xray.log').open('w') as log:
        core=subprocess.Popen(['/opt/snell-network/xray','run','-c',str(config)],stdout=log,stderr=log)
        try:
            time.sleep(.5)
            assert core.poll() is None
            subprocess.run(['/usr/local/bin/snell-routing.sh','--mode','xray'],env=env,check=True,stdout=subprocess.DEVNULL)
            original=state.snell_policy()
            assert original['owned'] and original['rules'] and original['routes']
            with (temp/'install.log').open('w') as output:
                result=subprocess.run(['bash',str(ROOT/'install.sh'),'--update'],env=env,stdout=output,stderr=subprocess.STDOUT)
            assert result.returncode==0,'Update failed; inspect private lab log'
            assert state.snell_policy()==original
            subprocess.run(['systemctl','is-active','--quiet','snell'],check=True)
            # Actual failure after Snell is restarted exercises full transaction rollback.
            subprocess.run(['python3',str(ROOT/'tests/lab-upgrade.py'),'seed'],env=env,check=True,stdout=subprocess.DEVNULL)
            subprocess.run(['python3',str(ROOT/'tests/lab-failures.py'),'service'],env=env,check=True)
            assert state.snell_policy()==original
            print('PASS active TPROXY installation update and service-failure rollback preserve policy',flush=True)
        finally:
            # Restore the original direct installation while core is still alive.
            state.restore(backup)
            assert not state.snell_policy()['rules'] and not state.snell_policy()['routes']
            assert Path('/etc/snell/routing.mode').read_text().strip()=='direct'
            core.terminate();core.wait(timeout=5)
            print('PASS rollback to pre-TPROXY snapshot removes policy resources and restores direct mode',flush=True)
