"""Fault injection against the actual installer and systemd in a disposable lab."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

assert Path('/.x-manager-test-lab').exists(), 'Disposable lab only'
ROOT = Path('/work/x-manager')


def run_failure(source, label, env=None):
    with open('/tmp/x-manager-failure-' + label + '.log', 'w') as log:
        result = subprocess.run(['bash', str(source / 'install.sh'), '--update'], env=env, stdout=log, stderr=subprocess.STDOUT)
    assert result.returncode != 0, label + ' reported false success'
    output = Path('/tmp/x-manager-failure-' + label + '.log').read_text()
    assert 'Another installation' not in output, 'Wrong failure: concurrent installer'
    if label == 'service':
        assert 'Service failed: mita' in output or 'Service exited after startup: mita' in output, 'Expected actual Mieru failure'
    else:
        assert 'Injected ' + label + ' failure' in output
    subprocess.run(['python3', str(ROOT / 'tests/lab-upgrade.py'), 'check'], check=True)
    print('PASS: ' + label + ' fails clearly and preserves/restores existing installation')


mode = sys.argv[1]
source = Path(tempfile.mkdtemp(prefix='x-manager-failure-source-'))
shutil.copytree(ROOT, source, dirs_exist_ok=True, ignore=shutil.ignore_patterns('.git', '__pycache__'))
if mode in ('dependency', 'download'):
    tools = Path(tempfile.mkdtemp(prefix='x-manager-failure-tools-'))
    name = 'apt-get' if mode == 'dependency' else 'curl'
    command = tools / name
    command.write_text('#!/bin/sh\necho "Injected ' + mode + ' failure" >&2\nexit 22\n')
    command.chmod(0o755)
    run_failure(source, mode, dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH']))
elif mode == 'service':
    # The real newly installed service exits with failure. No systemctl mock.
    installer = source / 'install.sh'
    original = installer.read_text()
    assert 'ExecStart=${which_mita} run' in original
    installer.write_text(original.replace('ExecStart=${which_mita} run', 'ExecStart=/bin/false'))
    run_failure(source, mode)
elif mode == 'config':
    config = Path('/etc/mita/config.json')
    before = config.read_bytes()
    try:
        config.write_text('{invalid configuration')
        with open('/tmp/x-manager-failure-config.log', 'w') as log:
            result = subprocess.run(['bash', str(source / 'install.sh'), '--update'], stdout=log, stderr=subprocess.STDOUT)
        assert result.returncode != 0
        assert 'Port preflight failed' in Path('/tmp/x-manager-failure-config.log').read_text(), 'Expected configuration failure, not another error'
        assert config.read_text() == '{invalid configuration'
    finally:
        config.write_bytes(before)
    subprocess.run(['python3', str(ROOT / 'tests/lab-upgrade.py'), 'check'], check=True)
    print('PASS: invalid configuration rejected before replacing files; original restored by test harness')
else:
    raise SystemExit('Unknown case')
