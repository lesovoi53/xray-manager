#!/usr/bin/env python3
"""Fetch immutable, hash-checked assets from the project's own release only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

REPOSITORY = 'lesovoi53/xray-manager'


def digest(path):
    value = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def fetch(manifest, asset, destination, local=None):
    if manifest['repository'] != REPOSITORY or not re.fullmatch(r'v[0-9][A-Za-z0-9._-]*', manifest['release']):
        raise ValueError('Invalid release identity')
    expected = manifest['sha256'][asset]
    if not re.fullmatch(r'[a-f0-9]{64}', expected) or Path(asset).name != asset:
        raise ValueError('Invalid asset manifest')
    destination = Path(destination)
    with tempfile.TemporaryDirectory(dir=destination.parent) as work:
        staged = Path(work) / asset
        if local:
            shutil.copyfile(Path(local) / asset, staged)
        else:
            url = 'https://github.com/%s/releases/download/%s/%s' % (REPOSITORY, manifest['release'], asset)
            subprocess.run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
                            '--connect-timeout', '15', '--max-time', '300', '--retry', '2',
                            '--output', str(staged), url], check=True)
        if digest(staged) != expected:
            raise ValueError('SHA-256 mismatch: ' + asset + '; installed files were not changed')
        os.replace(staged, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('asset', help='Use {arch} for amd64')
    parser.add_argument('destination')
    parser.add_argument('--manifest', default=str(Path(__file__).resolve().parent.parent / 'components.json'))
    args = parser.parse_args()
    arch = {'x86_64': 'amd64'}.get(platform.machine())
    if not arch:
        raise ValueError('Unsupported architecture')
    fetch(json.loads(Path(args.manifest).read_text()), args.asset.format(arch=arch), args.destination,
          os.environ.get('XM_COMPONENT_DIR'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit('Component download failed: ' + str(error))
