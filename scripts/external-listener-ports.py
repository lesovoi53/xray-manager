"""Read-only installer discovery of existing WDTT/CSQTT listener ports."""
import glob
import ipaddress
from pathlib import Path
import re
import shlex
import subprocess
import sys

UNITS = {'WDTT_PORT': 'wdtt.service', 'CSQTT_PORT': 'csqtt.service'}
SHELLS = {'sh', 'bash', 'dash', 'zsh', 'fish', 'env', 'sudo', 'su'}


def listener_port(argv):
    if not argv or Path(argv[0]).name in SHELLS:
        raise ValueError('Listener command uses an unsupported wrapper')
    values = []
    index = 1
    while index < len(argv):
        word = argv[index]
        if word == '--':
            break
        if word in ('-listen', '--listen'):
            index += 1
            if index >= len(argv):
                raise ValueError('Missing listener address')
            values.append(argv[index])
        elif word.startswith(('-listen=', '--listen=')):
            values.append(word.split('=', 1)[1])
        index += 1
    if len(values) != 1:
        raise ValueError('Expected exactly one explicit listener address')
    address = values[0]
    if address.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\]:([0-9]+)', address)
        if not match:
            raise ValueError('Invalid IPv6 listener address')
        try:
            ipaddress.IPv6Address(match[1])
        except ValueError:
            raise ValueError('Invalid IPv6 listener address') from None
        port = match[2]
    else:
        match = re.fullmatch(r'([^:\s]*):([0-9]+)', address)
        if not match:
            raise ValueError('Invalid listener address')
        host, port = match.groups()
        if host and not re.fullmatch(r'[A-Za-z0-9_.-]+', host):
            raise ValueError('Invalid listener host')
        if host and re.fullmatch(r'[0-9.]+', host):
            try:
                ipaddress.IPv4Address(host)
            except ValueError:
                raise ValueError('Invalid IPv4 listener address') from None
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError('Listener port outside 1..65535')
    return number


def environment(properties, root):
    values = {}
    for item in shlex.split(properties.get('Environment', '')):
        key, separator, value = item.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            raise ValueError('Invalid systemd environment')
        values[key] = value
    files = properties.get('EnvironmentFiles', '').strip()
    while files:
        match = re.match(r'(.+?) \(ignore_errors=(yes|no)\)(?:\s+|$)', files)
        if not match:
            raise ValueError('Cannot parse systemd EnvironmentFiles')
        names = shlex.split(match[1])
        if len(names) != 1 or not Path(names[0]).is_absolute():
            raise ValueError('Unsupported EnvironmentFile path')
        paths = sorted(glob.glob(str(root/names[0].lstrip('/'))))
        if not paths and match[2] != 'yes':
            raise ValueError('Required EnvironmentFile is missing')
        for filename in paths:
            text = Path(filename).read_text().replace('\\\n', '')
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(('#', ';')):
                    continue
                key, separator, value = line.partition('=')
                key = key.strip()
                if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                    continue  # systemd ignores non-assignment lines as well.
                values[key] = ' '.join(shlex.split(value, comments=False))
        files = files[match.end():]
    for item in shlex.split(properties.get('UnsetEnvironment', '')):
        key, separator, value = item.partition('=')
        if not separator or values.get(key) == value:
            values.pop(key, None)
    return values


def configured_argv(properties, root):
    command = properties.get('ExecStart', '')
    if command.count('argv[]=') != 1:
        raise ValueError('Expected one systemd ExecStart command')
    match = re.search(r'argv\[\]=(.*?) ; ignore_errors=', command)
    if not match:
        raise ValueError('Cannot parse systemd ExecStart')
    values = environment(properties, root)
    result = []
    def lookup(name):
        if name not in values:
            raise ValueError('Listener command has unresolved environment variables')
        return values[name]
    for argument in shlex.split(match[1]):
        argument = argument.replace('$$', '\x00')
        standalone = re.fullmatch(r'\$([A-Za-z_][A-Za-z0-9_]*)', argument)
        if standalone:
            result.extend(shlex.split(lookup(standalone[1])))
        else:
            argument = re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', lambda match: lookup(match[1]), argument)
            if '$' in argument:
                raise ValueError('Unsupported environment expansion in ExecStart')
            result.append(argument.replace('\x00', '$'))
    return result


def discover(unit, root=Path('/')):
    result = subprocess.run(['systemctl', 'show', unit,
                             '--property=LoadState,ActiveState,MainPID,ExecStart,Environment,EnvironmentFiles,UnsetEnvironment'],
                            capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise ValueError('Cannot inspect '+unit)
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if properties.get('LoadState') in ('not-found', 'masked'):
        return None
    if properties.get('LoadState') != 'loaded':
        raise ValueError('Cannot inspect loaded state of '+unit)
    if properties.get('ActiveState') not in ('active', 'inactive', 'failed'):
        raise ValueError('Wait for a stable service state: '+unit)
    pid = properties.get('MainPID', '0')
    if not pid.isdigit():
        raise ValueError('Invalid systemd MainPID')
    if int(pid) and properties['ActiveState'] == 'active':
        # Runtime argv already has systemd/environment expansion, and reflects
        # the actual listener even if an administrator edited the unit since start.
        argv = (root/'proc'/pid/'cmdline').read_bytes().decode().rstrip('\x00').split('\x00')
    else:
        argv = configured_argv(properties, root)
    return listener_port(argv)


if __name__ == '__main__':
    try:
        selected = {key: discover(unit) for key, unit in UNITS.items()}
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        # Do not print ExecStart/environment: those can contain credentials.
        sys.exit('External listener preflight failed: '+str(error))
    for key, port in selected.items():
        print(key+'='+shlex.quote(str(port) if port is not None else ''))
