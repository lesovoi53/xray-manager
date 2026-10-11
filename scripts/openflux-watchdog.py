#!/usr/bin/env python3
"""Persistent, shared automatic-recovery budget for all eight OpenFlux slots.

ExecCondition skips an exhausted automatic start (exit 1), so systemd does not
schedule another restart. Initial/manual starts do not spend this budget.
"""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

UNITS = tuple('openflux@%d.service' % i for i in range(1, 9))
CONFIG = '/etc/x-manager/openflux-watchdog.json'
STATE = '/var/lib/x-manager/openflux-watchdog/state.json'
LOCK = '/var/lib/x-manager/openflux-watchdog/lock'
DROPIN = '91-tuna-openflux-watchdog.conf'
OLD_DROPIN = '90-tuna-watchdog.conf'
HEADER = '# Managed by X-Manager openflux-watchdog.py; shared restart budget.\n'
HOOK = '/usr/local/share/x-manager/scripts/openflux-watchdog.py'


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('OpenFlux watchdog system command failed')
    return result.stdout.strip()


def canonical(unit):
    name = unit if unit.endswith('.service') else unit + '.service'
    if name not in UNITS:
        raise ValueError('OpenFlux watchdog supports only channels 1-8')
    return name


def validate(attempts, delay):
    if type(attempts) is not int or not 0 <= attempts <= 20 or type(delay) is not int or not 1 <= delay <= 3600:
        raise ValueError('OpenFlux attempts must be 0-20 and delay 1-3600 seconds')


def atomic(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class Watchdog:
    def __init__(self, root='/', run=command, controller=None, now=time.time):
        self.root, self.run = Path(root), run
        self.now = now
        if controller is None:
            spec = importlib.util.spec_from_file_location('openflux_lifecycle', Path(__file__).with_name('service-control.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            controller = module.Controller(self.root, run)
        self.controller = controller

    def path(self, name):
        target = self.root / name.lstrip('/')
        cursor = target
        while cursor != self.root:
            if cursor.is_symlink():
                raise ValueError('Symlink in managed OpenFlux watchdog path')
            cursor = cursor.parent
        return target

    @contextmanager
    def lock(self):
        path = self.path(LOCK)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        with path.open('a') as stream:
            if os.name == 'posix':
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def read(self, name):
        path = self.path(name)
        with path.open(encoding='utf-8') as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError('OpenFlux watchdog state exceeds bounded size')
        value = json.loads(data)
        if not isinstance(value, dict) or value.get('version') != 1:
            raise ValueError('Invalid OpenFlux watchdog state; explicit reset required')
        if name == CONFIG:
            if set(value) != {'version', 'attempts', 'delay'}:
                raise ValueError('Invalid OpenFlux watchdog configuration')
            validate(value['attempts'], value['delay'])
        elif (not {'version', 'spent', 'receipts'} <= set(value)
              or set(value) - {'version', 'spent', 'receipts', 'exhausted_at', 'pending', 'last_recovery', 'grants'}
              or type(value['spent']) is not int
              or not 0 <= value['spent'] <= 1000000 or not isinstance(value['receipts'], dict)
              or any(unit not in UNITS or not isinstance(token, str) or not 1 <= len(token) <= 128
                     for unit, token in value['receipts'].items())):
            raise ValueError('Invalid OpenFlux watchdog counter; explicit reset required')
        if name == STATE:
            if ('exhausted_at' in value and (type(value['exhausted_at']) is not int or value['exhausted_at'] < 0)
                    or 'last_recovery' in value and (type(value['last_recovery']) is not int or value['last_recovery'] < 0)
                    or not isinstance(value.get('pending', []), list)
                    or any(unit not in UNITS for unit in value.get('pending', []))
                    or len(value.get('pending', [])) != len(set(value.get('pending', [])))):
                raise ValueError('Invalid OpenFlux recovery state')
            grants = value.get('grants', {})
            if (not isinstance(grants, dict) or any(unit not in UNITS or type(at) is not int or at < 0
                                                    for unit, at in grants.items())):
                raise ValueError('Invalid OpenFlux recovery grants')
        return value

    def status(self):
        if not self.path(CONFIG).exists():
            return {'configured': False, 'attempts': None, 'delay': None, 'spent': None,
                    'remaining': None, 'exhausted': False}
        config, state = self.read(CONFIG), self.read(STATE)
        remaining = max(0, config['attempts'] - state['spent'])
        return {'configured': True, 'attempts': config['attempts'], 'delay': config['delay'],
                'spent': state['spent'], 'remaining': remaining, 'exhausted': remaining == 0,
                'retry_after': max(0, 300 - max(0, int(self.now()) - state.get('exhausted_at', int(self.now()))))
                    if remaining == 0 and config['attempts'] else 0,
                'pending': state.get('pending', [])}

    def conflicts(self):
        if any(row.get('conflict') or row.get('ActiveState') == 'deactivating'
               for row in self.controller.conflicts()):
            raise ValueError('External watchdog is active; select a single recovery owner first')

    def reserve(self, unit, token=None):
        unit = canonical(unit)
        token = token or 'health:' + uuid.uuid4().hex
        if not isinstance(token, str) or not 1 <= len(token) <= 128:
            raise ValueError('Invalid OpenFlux restart receipt')
        with self.lock():
            self.conflicts()
            if not self.controller.allowed(unit):
                return False
            config, state = self.read(CONFIG), self.read(STATE)
            if state['receipts'].get(unit) == token:
                return True
            if state['spent'] >= config['attempts']:
                if config['attempts'] and token.startswith('systemd:'):
                    state.setdefault('exhausted_at', int(self.now()))
                    state['pending'] = sorted(set(state.get('pending', [])) | {unit})
                    atomic(self.path(STATE), encoded(state))
                return False
            state['spent'] += 1
            state['receipts'][unit] = token
            if state['spent'] >= config['attempts']:
                state['exhausted_at'] = int(self.now())
            atomic(self.path(STATE), encoded(state))
            return True

    def show(self, unit):
        properties = 'LoadState,ActiveState,Result,UnitFileState,Type,DropInPaths,Restart,RestartUSec,StartLimitIntervalUSec,NRestarts,InvocationID,ExecCondition'
        output = self.run('systemctl', 'show', unit, '--property=' + properties)
        return dict(line.split('=', 1) for line in output.splitlines() if '=' in line)

    def gate(self, unit):
        unit = canonical(unit)
        if not self.controller.allowed(unit):
            return False
        # Read both even for the initial start: missing/corrupt state fails closed.
        self.read(CONFIG)
        self.read(STATE)
        live = self.show(unit)
        count = live.get('NRestarts', '')
        if not count.isdigit():
            raise ValueError('Cannot identify systemd restart type')
        invocation = live.get('InvocationID', '')
        if not re.fullmatch(r'[a-fA-F0-9]{32}', invocation):
            return False  # Inactive/garbage-collected units are not a start.
        # A timer restart was already charged before requesting systemd. Its
        # ExecCondition must consume that grant rather than charge twice.
        with self.lock():
            state = self.read(STATE)
            grant = state.get('grants', {}).pop(unit, None)
            if grant is not None:
                valid = 0 <= int(self.now()) - grant <= 60
                if valid:
                    state['receipts'][unit] = 'systemd:' + invocation.lower()
                atomic(self.path(STATE), encoded(state))
                if valid:
                    self.conflicts()
                    return True
        if int(count) == 0:
            # Ownership conflicts must inhibit automatic recovery, never an
            # explicit start (which service-control resets before invoking).
            return True
        return self.reserve(unit, 'systemd:' + invocation.lower())

    def reset(self):
        with self.lock():
            self.read(CONFIG)
            atomic(self.path(STATE), encoded({'version': 1, 'spent': 0, 'receipts': {}}))
        return self.status()

    def recover(self):
        """Resume only channels stopped by our exhausted ExecCondition.

        Called by the recovery timer while holding the installer lock. Queued
        starts must be nonblocking: their ExecCondition takes our budget lock.
        """
        if not self.path(CONFIG).exists():
            return {'status': 'unconfigured', 'started': []}
        with self.controller.lock(), self.lock():
            self.conflicts()
            config, state = self.read(CONFIG), self.read(STATE)
            started = []
            if not config['attempts']:
                return {'status': 'disabled', 'started': started}
            now = int(self.now())
            if state['spent'] >= config['attempts']:
                since = state.setdefault('exhausted_at', now)
                if now < since:
                    state['exhausted_at'] = now
                if now - state['exhausted_at'] < 300:
                    atomic(self.path(STATE), encoded(state))
                    return {'status': 'cooldown', 'started': started}
                state.update(spent=0, receipts={})
                state.pop('exhausted_at', None)
            last = state.get('last_recovery')
            if last is not None and now < last:
                state['last_recovery'] = now
                atomic(self.path(STATE), encoded(state))
                return {'status': 'cooldown', 'started': started}
            if last is not None and now - last < config['delay']:
                return {'status': 'cooldown', 'started': started}
            for unit in list(state.get('pending', [])):
                live = self.show(unit)
                policy = self.path('/etc/systemd/system/' + unit + '.d/' + DROPIN)
                eligible = (self.controller.allowed(unit) and live.get('LoadState') == 'loaded'
                            and not live.get('UnitFileState', '').startswith('masked')
                            and live.get('ActiveState') == 'inactive'
                            and live.get('Result') == 'exec-condition'
                            and policy.exists() and policy.read_bytes() == self.render(config['attempts'], config['delay']))
                if not eligible:
                    # A manual stop clears Result; never undo it or an off marker.
                    state['pending'].remove(unit)
                    continue
                if state['spent'] >= config['attempts']:
                    break
                state['spent'] += 1
                state['last_recovery'] = now
                state.setdefault('grants', {})[unit] = now
                if state['spent'] >= config['attempts']:
                    state['exhausted_at'] = now
                atomic(self.path(STATE), encoded(state))
                # Shared policies disable the systemd start limiter. Clearing
                # Result here would lose our exec-condition evidence if start
                # fails, and could confuse a later manual stop with our queue.
                try:
                    self.run('systemctl', 'start', '--no-block', unit)
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    state['grants'].pop(unit, None)
                    atomic(self.path(STATE), encoded(state))
                    raise
                state['pending'].remove(unit)
                atomic(self.path(STATE), encoded(state))
                started.append(unit)
            atomic(self.path(STATE), encoded(state))
            return {'status': 'checked', 'started': started}

    def render(self, attempts, delay):
        validate(attempts, delay)
        return (HEADER + '[Unit]\nStartLimitIntervalSec=0\n[Service]\n'
                'Restart=' + ('on-failure' if attempts else 'no') + '\nRestartSec=' + str(delay) + 's\n'
                'ExecCondition=+/usr/bin/python3 ' + HOOK + ' gate --unit %n\n').encode()

    def owned_old(self, data):
        return re.fullmatch(
            rb'# Managed by TUNA watchdog; reset limit explicitly from the menu\.\n\[Unit\]\n'
            rb'StartLimitIntervalSec=infinity\nStartLimitBurst=(?:[1-9]|1[0-9]|2[01])\n\[Service\]\n'
            rb'Restart=(?:on-failure|no)\nRestartSec=[0-9]+s\n', data) is not None

    def preflight(self, unit, live):
        directory = self.path('/etc/systemd/system/' + unit + '.d')
        paths = set(directory.glob('*.conf'))
        paths.update(self.path('/etc/systemd/system/service.d').glob('*.conf'))
        template = unit.split('@')[0] + '@.service.d'
        paths.update(self.path('/etc/systemd/system/' + template).glob('*.conf'))
        for token in live.get('DropInPaths', '').split():
            name = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m[1], 16)), token)
            paths.add(self.path(name))
        old = None
        for path in paths:
            if path.is_symlink():
                raise ValueError('Foreign OpenFlux watchdog override')
            data = path.read_bytes()
            if path == directory / DROPIN:
                if not data.startswith(HEADER.encode()):
                    raise ValueError('Foreign OpenFlux shared policy')
                # Only exact generated policies belong to us.
                if data != self.render(*self._existing_policy(data)):
                    raise ValueError('Modified OpenFlux shared policy')
            elif path == directory / OLD_DROPIN and self.owned_old(data):
                old = path
            elif (path.name == '95-tuna-service-control.conf'
                  and data.startswith(b'# Managed by X-Manager service-control.py; use its lifecycle commands.\n')):
                continue
            elif re.search(rb'^\s*(?:Restart\w*|StartLimit\w*|ExecCondition)\s*=', data, re.MULTILINE):
                raise ValueError('Foreign OpenFlux restart policy; existing files were preserved')
        return old

    def _existing_policy(self, data):
        delay = re.search(rb'^RestartSec=(\d+)s$', data, re.MULTILINE)
        if not delay:
            raise ValueError('Modified OpenFlux shared policy')
        return (1 if b'Restart=on-failure\n' in data else 0), int(delay[1])

    def verify(self, unit, attempts, delay):
        live = self.show(unit)
        off = self.controller.status(unit)['off']
        wanted = 'on-failure' if attempts and not off else 'no'
        parts = re.findall(r'(\d+(?:\.\d+)?)(us|ms|min|h|s)', live.get('RestartUSec', '').replace(' ', ''))
        seconds = sum(float(value) * {'us': .000001, 'ms': .001, 's': 1, 'min': 60, 'h': 3600}[suffix]
                      for value, suffix in parts)
        if (live.get('Restart') != wanted or live.get('StartLimitIntervalUSec') != '0'
                or not parts or abs(seconds - delay) > .000001 or HOOK not in live.get('ExecCondition', '')):
            raise ValueError('Effective OpenFlux shared restart policy was not confirmed')

    def configure(self, attempts=5, delay=5):
        policy = self.render(attempts, delay)
        self.conflicts()
        with self.controller.lock(), self.lock():
            self.conflicts()
            plan, skipped, inherited = {}, [], 0
            for unit in UNITS:
                live = self.show(unit)
                if live.get('LoadState') != 'loaded' or live.get('Type') == 'oneshot':
                    skipped.append(unit)
                    continue
                old = self.preflight(unit, live)
                plan[self.path('/etc/systemd/system/' + unit + '.d/' + DROPIN)] = policy
                if old is not None:
                    plan[old] = None
                count = live.get('NRestarts', '')
                if not count.isdigit():
                    raise ValueError('Cannot preserve existing OpenFlux restart counts')
                inherited += int(count)
            result = {'changed': [], 'skipped': skipped, 'backup': None}
            if not plan:
                return result
            configured = self.path(CONFIG).exists()
            if configured:
                self.read(CONFIG)
                self.read(STATE)
            elif self.path(STATE).exists():
                # A detached counter still must never refill on configuration.
                self.read(STATE)
            else:
                plan[self.path(STATE)] = encoded({'version': 1, 'spent': inherited, 'receipts': {}})
            plan[self.path(CONFIG)] = encoded({'version': 1, 'attempts': attempts, 'delay': delay})
            old = {path: (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else (None, 0o600)
                   for path in plan}
            plan = {path: data for path, data in plan.items() if old[path][0] != data}
            if not plan:
                for unit in UNITS:
                    if unit not in skipped:
                        self.verify(unit, attempts, delay)
                return result
            backup_root = self.path('/var/backups')
            backup_root.mkdir(parents=True, exist_ok=True)
            backup = Path(tempfile.mkdtemp(prefix='openflux-watchdog-', dir=backup_root))
            records = []
            for index, path in enumerate(plan):
                content, mode = old[path]
                records.append({'path': str(path), 'existed': content is not None, 'mode': mode, 'copy': str(index)})
                if content is not None:
                    atomic(backup / str(index), content, mode)
            atomic(backup / 'state.json', encoded({'files': records}))
            written, created = [], []
            try:
                for path, data in plan.items():
                    if not path.parent.exists():
                        created.append(path.parent)
                    written.append(path)
                    if data is None:
                        path.unlink()
                    else:
                        atomic(path, data, 0o644 if path.name == DROPIN else 0o600)
                self.run('systemctl', 'daemon-reload')
                for unit in UNITS:
                    if unit not in skipped:
                        self.verify(unit, attempts, delay)
            except BaseException:
                for path in reversed(written):
                    content, mode = old[path]
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic(path, content, mode)
                for directory in reversed(created):
                    if directory.exists() and not any(directory.iterdir()):
                        directory.rmdir()
                self.run('systemctl', 'daemon-reload')
                raise
            result.update(changed=[unit for unit in UNITS if unit not in skipped], backup=str(backup))
            return result


def configure(attempts=5, delay=5):
    return Watchdog().configure(attempts, delay)


def status():
    return Watchdog().status()


def reset():
    return Watchdog().reset()


def reserve(unit, token=None):
    return Watchdog().reserve(unit, token)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['configure', 'status', 'reset', 'gate'])
    parser.add_argument('--attempts', type=int, default=5)
    parser.add_argument('--delay', type=int, default=5)
    parser.add_argument('--unit')
    args = parser.parse_args()
    watchdog = Watchdog()
    if args.action == 'gate':
        return 0 if watchdog.gate(args.unit or '') else 1
    result = watchdog.configure(args.attempts, args.delay) if args.action == 'configure' else getattr(watchdog, args.action)()
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        # Exit 1 is an unmet ExecCondition, not a failed service/restart loop.
        detail = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
        print('OpenFlux watchdog: запуск отклонён: ' + detail, file=sys.stderr)
        raise SystemExit(1)
