"""Native systemd acceptance in the disposable Debian lab, with a fake exit binary."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parents[1]


def ctl(*args, check=True):
    return subprocess.run(["systemctl", *args], check=check, capture_output=True,
                          text=True, timeout=20)


def main():
    assert os.geteuid() == 0 and Path('/.x-manager-test-lab').is_file()
    assert Path('/run/systemd/container').read_text().strip() == 'systemd-nspawn'
    unit = 'qa-openflux-memory.service'
    template = Path('/etc/systemd/system') / unit
    assert not template.exists()
    cases = []
    with tempfile.TemporaryDirectory(prefix='qa-openflux-memory-') as directory:
        root = Path(directory)
        root.chmod(0o755)
        def write(name, value, mode=0o644):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
            path.chmod(mode)
            return path
        write('proc/meminfo', 'MemTotal: 990208 kB\n')
        for channel in (1, 2, 3):
            write(f'etc/openflux/instances/{channel}.env', 'URL=fixture\nTRANSPORT=fixture\nDEBUG=0\n')
        binary = write('exit', '#!/bin/sh\nprintf "LIMIT=%s\\n" "$GOMEMLIMIT"\n', 0o755)
        runner = (SOURCE / 'scripts/openflux-runner.sh').read_text().replace('/etc/', str(root / 'etc') + '/').replace('/usr/local/bin/openflux', str(binary))
        runner_path = write('runner', runner, 0o755)
        production = (SOURCE / 'systemd/openflux@.service').read_text()
        hook = next(line for line in production.splitlines() if 'openflux-resources.py auto' in line)
        hook = hook.replace('/usr/local/share/x-manager', str(SOURCE)) + ' --root ' + str(root)
        output = root / 'output'
        template.write_text(f'[Service]\nType=oneshot\nUser=nobody\n{hook}\nExecStart={runner_path} 1\nStandardOutput=file:{output}\n')
        try:
            ctl('daemon-reload')
            ctl('start', unit)
            assert 'LIMIT=114MiB' in output.read_text()
            config = root / 'etc/openflux/resources.conf'
            saved = config.read_bytes()
            ctl('start', unit)
            assert config.read_bytes() == saved
            assert len(list((root / 'var/lib/x-manager/openflux-resources').glob('*.json'))) == 1
            cases.extend(['root pre-start with unprivileged runner', 'effective 114 MiB', 'repeat unchanged'])
            config.write_text('# manual choice\n1=100MiB\n2=100MiB\n3=100MiB\n')
            ctl('start', unit)
            assert 'LIMIT=100MiB' in output.read_text()
            assert config.read_text().startswith('# manual choice')
            cases.append('manual choice preserved and used')
            config.write_bytes(saved)
            write('proc/meminfo', 'MemTotal: 524288 kB\n')
            output.write_text('runner must not execute\n')
            failure = ctl('start', unit, check=False)
            assert failure.returncode != 0
            assert 'LIMIT=' not in output.read_text()
            assert config.read_bytes() == saved
            assert ctl('show', unit, '-p', 'Result', '--value').stdout.strip() == 'exit-code'
            cases.append('insufficient memory blocks start, keeps previous budget')
        finally:
            ctl('stop', unit, check=False)
            template.unlink()
            ctl('daemon-reload')
            ctl('reset-failed', check=False)
    print(json.dumps({'passed': len(cases), 'cases': cases}, ensure_ascii=False))


if __name__ == '__main__':
    main()
