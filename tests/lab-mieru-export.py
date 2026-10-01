"""Actual daemon RPC -> export -> native codec, in disposable systemd lab only."""
import importlib.util
import json
from pathlib import Path
import subprocess

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab only'
ROOT=Path('/work/x-manager')
spec=importlib.util.spec_from_file_location('mieru_export',ROOT/'scripts/mieru-subscriptions.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
path=Path('/etc/mita/config.json');before=path.read_bytes()
try:
    config=json.loads(before)
    for mode in ('LOW_ENTROPY_MODE_32','LOW_ENTROPY_MODE_48'):
        config.setdefault('trafficPattern',{}).setdefault('lowEntropy',{}).update(mode=mode,maskRotation='LOW_ENTROPY_MASK_ROTATE_RIGHT_7')
        path.write_text(json.dumps(config))
        subprocess.run(['systemctl','restart','mita'],check=True)
        # Wait for RPC, bounded and without exposing daemon diagnostics.
        import time
        for attempt in range(30):
            try:value=m.snapshot();break
            except Exception:
                if attempt==29:raise
                time.sleep(.1)
        user=value['config']['users'][0]['name']
        uri=m.export(value,'192.0.2.1',user,'Mieru-Home')['uri']
        parsed=m.validate(uri)
        assert parsed['low-entropy-mode']==mode
        assert m.decode(parsed['traffic-pattern'])==value['config']['trafficPattern']
        print('PASS actual Mita RPC/export/native decode: '+mode,flush=True)
finally:
    path.write_bytes(before)
    subprocess.run(['systemctl','restart','mita'],check=True)
    assert path.read_bytes()==before
