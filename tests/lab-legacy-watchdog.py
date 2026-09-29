"""Real systemd migration/rollback acceptance; disposable lab ONLY."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab only'
ROOT = Path('/work/x-manager')
UNIT = Path('/etc/systemd/system/tuna-watchdog.service')
TIMER = Path('/etc/systemd/system/tuna-watchdog.timer')
assert not UNIT.exists() and not TIMER.exists(), 'Refusing to replace existing legacy units'
env = dict(os.environ, XM_COMPONENT_DIR='/opt/xm-assets')


def ctl(*args):
    return subprocess.run(['systemctl', *args], check=True, capture_output=True, text=True)


def overrides():
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in Path('/etc/systemd/system').glob('*.service.d/90-tuna-watchdog.conf')}


def install(root, label, migrate=True):
    log=Path('/tmp/watchdog-'+label+'.log')
    args=['bash',str(root/'install.sh'),'--update']
    if migrate:args.append('--migrate-legacy-watchdog')
    with log.open('w') as output:
        result=subprocess.run(args,env=env,stdout=output,stderr=subprocess.STDOUT)
    return result.returncode,log.read_text()


try:
    UNIT.write_text('[Service]\nType=oneshot\nExecStart=/bin/true\n')
    TIMER.write_text('[Timer]\nOnActiveSec=10min\nOnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\n')
    ctl('daemon-reload');ctl('enable','--now',TIMER.name)
    before=overrides()
    count=len(list(Path('/var/backups').glob('x-manager-*/state.json')))
    code,log=install(ROOT,'guard',False)
    assert code!=0 and 'Legacy watchdog is active' in log
    assert len(list(Path('/var/backups').glob('x-manager-*/state.json')))==count
    ctl('is-active','--quiet',TIMER.name)
    assert overrides()==before
    print('PASS legacy watchdog blocks unattended update before managed changes',flush=True)

    with tempfile.TemporaryDirectory(prefix='watchdog-fault-') as tmp:
        copy=Path(tmp)/'source';shutil.copytree(ROOT,copy,ignore=shutil.ignore_patterns('.git','__pycache__'))
        p=copy/'install.sh';s=p.read_text()
        anchor='    XM_WATCHDOG_TRANSACTION=1 python3 "$SCRIPT_DIR/scripts/tuna-watchdog.py" retire-legacy --attempts 3 --delay 30'
        assert anchor in s
        p.write_text(s.replace(anchor,anchor+'\n    xm_die "Injected watchdog migration failure"'))
        code,log=install(copy,'fault')
        assert code!=0 and 'Injected watchdog migration failure' in log
        assert 'ROLLBACK FAILED' not in log,log[-500:]
    ctl('is-active','--quiet',TIMER.name);ctl('is-enabled','--quiet',TIMER.name)
    assert overrides()==before
    print('PASS injected failure restores old timer and every watchdog override',flush=True)

    code,log=install(ROOT,'success')
    assert code==0,log[-500:]
    assert subprocess.run(['systemctl','is-active','--quiet',TIMER.name]).returncode!=0
    assert subprocess.run(['systemctl','is-enabled','--quiet',TIMER.name]).returncode!=0
    for service in ('snell','mita','webdav-tunnel','tuna-subscriptions'):
        ctl('is-active','--quiet',service)
        props=ctl('show',service,'-p','Restart','-p','StartLimitBurst','-p','StartLimitIntervalUSec').stdout
        assert 'Restart=on-failure' in props and 'StartLimitBurst=4' in props and 'StartLimitIntervalUSec=infinity' in props
    print('PASS migration disables old timer and applies bounded policies to active services',flush=True)
    command=re.search(r'^Rollback: (.+)$',log,re.M).group(1)
    subprocess.run(['bash','-c',command],env=env,check=True,capture_output=True)
    ctl('is-active','--quiet',TIMER.name);ctl('is-enabled','--quiet',TIMER.name)
    assert overrides()==before
    print('PASS manual rollback restores old timer and original overrides',flush=True)
finally:
    ctl('disable','--now',TIMER.name)
    ctl('stop',UNIT.name)
    UNIT.unlink();TIMER.unlink();ctl('daemon-reload')
