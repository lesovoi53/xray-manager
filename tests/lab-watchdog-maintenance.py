"""Real systemd acceptance, only in the pre-existing private Debian lab."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab required'
assert 'VERSION_ID="13"' in Path('/etc/os-release').read_text()
source=Path('/work/x-manager/scripts/installer-state.py')
spec=importlib.util.spec_from_file_location('maintenance',source)
state=importlib.util.module_from_spec(spec);spec.loader.exec_module(state)
service='x-manager-qa-maintenance.service';timer='x-manager-qa-maintenance.timer'
units=(timer,service)
state.EXTERNAL_WATCHDOGS=units
def ctl(*args):
    return subprocess.run(['systemctl',*args],check=True,capture_output=True,text=True).stdout
def check():
    for unit in units:
        assert state.watchdog_state(unit)['ActiveState']=='inactive'
state.check_external_watchdog=check
paths=[Path('/run/systemd/system',u) for u in units]
assert all(not p.exists() for p in paths), 'QA units already exist'
try:
    paths[1].write_text('[Unit]\nDescription=X-Manager isolated maintenance acceptance\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\n')
    paths[0].write_text('[Unit]\nDescription=X-Manager isolated maintenance acceptance timer\n[Timer]\nOnActiveSec=1h\nUnit='+service+'\n')
    ctl('daemon-reload')
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);state.MAINTENANCE=root/'marker.json'
        backup=root/'backup';backup.mkdir();(backup/'state.json').write_text('{}');(backup/'files.tar').write_bytes(b'')
        for active in ((),(service,),(timer,),units):
            ctl('stop',*units)
            for unit in active:ctl('start',unit)
            before={u:state.watchdog_state(u) for u in units}
            state.watchdog_pause(backup)
            check()
            state.watchdog_resume()
            after={u:state.watchdog_state(u) for u in units}
            assert before==after,(before,after)
            assert not state.MAINTENANCE.exists()
            print('PASS native systemd active set:', ','.join(active) or 'none',flush=True)
finally:
    ctl('stop',*units)
    for p in paths:p.unlink(missing_ok=True)
    ctl('daemon-reload')
