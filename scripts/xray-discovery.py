#!/usr/bin/env python3
"""Read standalone Xray JSON/JSONC configurations without changing the core."""
import json
import os
from pathlib import Path
import re
import socket
import sys

KEYS = ('XRAY_SOCKS_PORT', 'XRAY_REDIRECT_PORT', 'XRAY_TPROXY_PORT')


def jsonc(text):
    # Comments are removed only outside JSON strings (URLs remain unchanged).
    pattern = r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/'
    return json.loads(re.sub(pattern, lambda m: m[0] if m[0].startswith('"') else ' ', text))


def discover(paths):
    found = {key: set() for key in KEYS}
    for path in paths:
        data = jsonc(Path(path).read_text())
        for inbound in data.get('inbounds', []):
            settings = inbound.get('settings', {})
            if inbound.get('listen', '0.0.0.0') != '127.0.0.1':
                continue  # Routing helpers connect via IPv4 loopback.
            protocol = inbound.get('protocol')
            key = None
            if protocol in ('socks', 'mixed') and settings.get('auth', 'noauth') == 'noauth':
                key = KEYS[0]
            elif protocol == 'dokodemo-door' and settings.get('followRedirect'):
                network = set(settings.get('network', 'tcp').split(','))
                tproxy = inbound.get('streamSettings', {}).get('sockopt', {}).get('tproxy')
                if tproxy == 'tproxy' and {'tcp', 'udp'} <= network:
                    key = KEYS[2]
                elif tproxy != 'tproxy' and 'tcp' in network:
                    key = KEYS[1]
            if key:
                port = int(inbound['port'])
                if not 1 <= port <= 65535 or port in (443, 8443):
                    raise ValueError('Forbidden Xray gateway port')
                found[key].add(port)
    result = {}
    for key, ports in found.items():
        explicit = os.environ.get(key)
        if explicit:
            if ports and int(explicit) not in ports:
                raise ValueError(key + ' does not match the Xray configuration')
            result[key] = int(explicit)
        elif len(ports) == 1:
            result[key] = ports.pop()
        elif len(ports) > 1:
            raise ValueError('Multiple gateways: set ' + key + ' explicitly')
    return result


def paths(root=Path('/')):
    explicit = os.environ.get('XM_XRAY_CONFIG')
    if explicit:
        p = Path(explicit)
        return sorted(p.glob('*.json')) if p.is_dir() else [p]
    candidates = []
    for relative in ('usr/local/etc/xray', 'etc/xray'):
        candidates.extend((root/relative).glob('*.json'))
    # Process arguments are used only to locate files; never printed or logged.
    if root == Path('/'):
        for proc in Path('/proc').glob('[0-9]*'):
            try:
                if not (proc/'exe').resolve().name.startswith('xray'):
                    continue
                args = (proc/'cmdline').read_bytes().decode().split('\0')
                for index, arg in enumerate(args[:-1]):
                    if arg in ('-config', '-c', '--config', '-confdir'):
                        p = Path(args[index+1])
                        if not p.is_absolute():
                            p = (proc/'cwd').resolve()/p
                        candidates.extend(p.glob('*.json') if p.is_dir() else [p])
            except (OSError, UnicodeError):
                continue
    return sorted(set(p for p in candidates if p.is_file()))


def verify(values):
    for key in KEYS:
        port = int(values[key])
        if port in (443, 8443) or not 1 <= port <= 65535:
            raise ValueError('Forbidden gateway port')
        with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
            if key == KEYS[0]:
                sock.sendall(b'\x05\x01\x00')
                if sock.recv(2) != b'\x05\x00':
                    raise ValueError('SOCKS5 gateway does not accept no-auth negotiation')


if __name__ == '__main__':
    try:
        result = discover(paths())
        if '--verify' in sys.argv:
            verify(dict(os.environ, **{k:str(v) for k,v in result.items()}))
        for key, value in result.items():
            print('%s=%d' % (key, value))
    except (OSError, ValueError, KeyError):
        sys.exit('Xray discovery failed. Set XM_XRAY_CONFIG to the active JSON/config directory and specify gateway ports if ambiguous. Existing Xray files were not changed.')
