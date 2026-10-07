import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, time
root = pathlib.Path(os.environ['QA_ROOT'])
who = os.environ['QA_INSTANCE']
active = root / 'active'
name = pathlib.Path(sys.argv[0]).name
if name == 'ip':
    print('inet 192.0.2.1/24 scope global fixture')
    raise SystemExit(0)
with (root / 'events').open('a') as out:
    out.write(who + ':' + name + '\n')
if name == 'iptables-save':
    try:
        with active.open('x') as out:
            out.write(who)
    except FileExistsError:
        print('overlapping routing transactions', file=sys.stderr)
        raise SystemExit(73)
    time.sleep(0.3)
    raise SystemExit(0)
if not active.exists() or active.read_text() != who:
    raise SystemExit(74)
path = root / 'state'
state = json.loads(path.read_text()) if path.exists() else {'chain': False, 'linked': False}
args = sys.argv[1:]
code = 0
if '-C' in args:
    code = 0 if state['linked'] else 1
elif '-D' in args:
    state['linked'] = False
elif '-S' in args:
    code = 0 if state['chain'] else 1
elif '-F' in args:
    code = 0 if state['chain'] else 1
elif '-X' in args:
    state['chain'] = False
elif '-N' in args:
    code = 1 if state['chain'] else 0
    state['chain'] = True
elif '-A' in args:
    code = 0 if state['chain'] else 1
elif '-I' in args:
    state['linked'] = True
    active.unlink()
path.write_text(json.dumps(state))
raise SystemExit(code)
'''


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash') and shutil.which('flock'),
                     'requires Linux bash and flock')
class OpenFluxRoutingLock(unittest.TestCase):
    def test_parallel_channels_serialize_whole_routing_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bindir = root / 'bin'
            bindir.mkdir()
            for name in ('iptables-save', 'iptables', 'ip'):
                path = bindir / name
                path.write_text(MOCK)
                path.chmod(0o755)
            # Only relocate hardcoded filesystem paths; execute the real shell
            # body, its actual flock, and concurrent child processes unchanged.
            source = (ROOT / 'scripts/openflux-routing.sh').read_text()
            source = source.replace('/run/lock/x-manager-openflux-routing.lock', str(root / 'routing.lock'))
            source = source.replace('/etc/openflux/routing.mode', str(root / 'routing.mode'))
            source = source.replace('/etc/x-manager/gateways.env', str(root / 'gateways.env'))
            (root / 'routing.mode').write_text('xray\n')
            script = root / 'routing.sh'
            script.write_text(source)
            env = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'], QA_ROOT=str(root))
            children = []
            try:
                first = subprocess.Popen(['bash', str(script)], env=dict(env, QA_INSTANCE='first'),
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append(first)
                deadline = time.monotonic() + 3
                while not (root / 'active').exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue((root / 'active').exists(), 'first transaction did not start')
                second = subprocess.Popen(['bash', str(script)], env=dict(env, QA_INSTANCE='second'),
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                children.append(second)
                outputs = [p.communicate(timeout=10) for p in children]
                self.assertEqual([p.returncode for p in children], [0, 0], outputs)
                owners = [line.split(':', 1)[0] for line in (root / 'events').read_text().splitlines()]
                runs = [owner for i, owner in enumerate(owners) if i == 0 or owners[i - 1] != owner]
                self.assertEqual(runs, ['first', 'second'], 'iptables transactions interleaved')
                self.assertFalse((root / 'active').exists())
            finally:
                for process in children:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()


if __name__ == '__main__':
    unittest.main()
