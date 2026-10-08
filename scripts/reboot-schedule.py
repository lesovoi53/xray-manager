#!/usr/bin/env python3
"""Explicit, opt-in reboot scheduling. Configuration never requests a reboot."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

TIMER = 'x-manager-reboot.timer'
SERVICE = 'x-manager-reboot.service'
CONFIG = '/etc/x-manager/reboot-schedule.json'
TIMER_FILE = '/etc/systemd/system/x-manager-reboot.timer'
LOCK = '/run/lock/x-manager-reboot.lock'
INSTALL_LOCK = '/run/lock/x-manager-install.lock'
MAINTENANCE = '/var/lib/x-manager/maintenance-watchdog.json'
HEADER = '# Managed by X-Manager reboot-schedule.py.\n'


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError('Command failed: '+' '.join(args))
    return result.stdout.strip()


def calendar(schedule_time, timezone):
    if not isinstance(schedule_time, str) or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', schedule_time):
        raise ValueError('Time must be HH:MM (00:00..23:59)')
    if not isinstance(timezone, str) or not re.fullmatch(r'[A-Za-z0-9_+/-]+', timezone):
        raise ValueError('Invalid timezone')
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError('Unknown timezone') from None
    return '*-*-* '+schedule_time+':00 '+timezone


def atomic_write(path, content, mode):
    if path.is_symlink():
        raise ValueError('Refusing symlink: '+str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Scheduler:
    def __init__(self, root=Path('/'), run=command):
        self.root, self.command = Path(root), run

    def path(self, name):
        return self.root/name.lstrip('/')

    def ctl(self, *args):
        return self.command('systemctl', *args)

    @contextmanager
    def lock(self, name=LOCK):
        path = self.path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def read(self):
        path = self.path(CONFIG)
        if path.is_symlink():
            raise ValueError('Reboot configuration is a symlink')
        if not path.exists():
            return {'version': 1, 'enabled': False, 'time': None, 'timezone': None}
        data = json.loads(path.read_text())
        if (not isinstance(data, dict) or data.get('version') != 1
                or type(data.get('enabled')) is not bool):
            raise ValueError('Invalid reboot configuration; existing state retained')
        if data.get('time') is not None or data.get('timezone') is not None or data['enabled']:
            calendar(data.get('time'), data.get('timezone'))
        return data

    def show(self, unit=TIMER):
        output = self.ctl('show', unit, '--property=LoadState,ActiveState,UnitFileState,MainPID,NextElapseUSecRealtime,LastTriggerUSecMonotonic')
        values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
        if values.get('LoadState') not in ('loaded', 'not-found', 'masked'):
            raise RuntimeError('Cannot verify unit state: '+unit)
        return values

    def foreign_conflicts(self):
        conflicts = []
        for unit in ('daily-reboot.timer', 'daily-reboot.service'):
            current = self.show(unit)
            if (current.get('ActiveState') not in ('inactive', 'failed')
                    or unit.endswith('.timer') and current.get('UnitFileState') in ('enabled', 'enabled-runtime')):
                conflicts.append(unit)
        return conflicts

    def backup(self, previous):
        directory = self.path('/var/backups')
        directory.mkdir(parents=True, exist_ok=True)
        backup = Path(tempfile.mkdtemp(prefix='x-manager-reboot-', dir=directory))
        files = []
        for index, name in enumerate((CONFIG, TIMER_FILE)):
            path = self.path(name)
            if path.is_symlink():
                raise ValueError('Refusing symlink: '+name)
            entry = {'path': name, 'exists': path.exists()}
            if entry['exists']:
                entry['mode'] = path.stat().st_mode & 0o777
                entry['uid'], entry['gid'] = path.stat().st_uid, path.stat().st_gid
                entry['backup'] = 'file-'+str(index)
                atomic_write(backup/entry['backup'], path.read_bytes(), 0o600)
            files.append(entry)
        record = {'version': 1, 'files': files, 'timer': previous}
        atomic_write(backup/'state.json', json.dumps(record).encode(), 0o600)
        return backup, record

    def restore(self, backup, record):
        previous = record['timer']
        current = self.show()
        if current.get('LoadState') == 'loaded':
            self.ctl('stop', TIMER)
            if previous.get('LoadState') == 'not-found':
                self.ctl('disable', TIMER)
        for entry in record['files']:
            path = self.path(entry['path'])
            if entry['exists']:
                atomic_write(path, (backup/entry['backup']).read_bytes(), entry['mode'])
                os.chown(path, entry['uid'], entry['gid'])
            else:
                path.unlink(missing_ok=True)
        self.ctl('daemon-reload')
        if previous.get('LoadState') == 'not-found':
            return
        enabled = previous.get('UnitFileState')
        if enabled == 'enabled-runtime':
            self.ctl('disable', TIMER)
            self.ctl('enable', '--runtime', TIMER)
        elif enabled == 'enabled':
            self.ctl('enable', TIMER)
        elif enabled == 'disabled':
            self.ctl('disable', TIMER)
        self.ctl('restart' if previous.get('ActiveState') == 'active' else 'stop', TIMER)

    def bootstrap(self):
        with self.lock() as acquired:
            if not acquired:
                raise RuntimeError('Reboot configuration is busy')
            if self.path(CONFIG).exists() or self.path(CONFIG).is_symlink():
                self.read()
                return {'changed': False, 'enabled': self.read()['enabled']}
            self.backup(self.show())
            atomic_write(self.path(CONFIG), json.dumps(self.read()).encode(), 0o600)
            return {'changed': True, 'enabled': False}

    def configure(self, schedule_time=None, timezone=None, enabled=True):
        with self.lock() as acquired:
            if not acquired:
                raise RuntimeError('Reboot configuration is busy')
            original = self.read()
            previous = self.show()
            if previous.get('LoadState') not in ('loaded', 'not-found') or previous.get('LoadState') == 'loaded' and previous.get('UnitFileState') not in ('enabled', 'enabled-runtime', 'disabled'):
                raise RuntimeError('Reboot timer is missing, masked or administrator-managed; state retained')
            if previous.get('ActiveState') not in ('active', 'inactive', 'failed'):
                raise RuntimeError('Reboot timer is transitioning; retry later')
            timer_file = self.path(TIMER_FILE)
            if timer_file.is_symlink() or timer_file.exists() and not timer_file.read_text().startswith(HEADER):
                raise RuntimeError('Foreign reboot timer unit; refusing to overwrite it')
            if previous.get('LoadState') == 'loaded' and not timer_file.exists():
                raise RuntimeError('Administrator-managed reboot timer; refusing to override it')
            if enabled:
                value = calendar(schedule_time, timezone)
                self.command('systemd-analyze', 'calendar', '--iterations=1', value)
                if self.show(SERVICE).get('LoadState') != 'loaded':
                    raise RuntimeError('Install the X-Manager reboot service before configuring its timer')
                conflicts = self.foreign_conflicts()
                if conflicts:
                    raise RuntimeError('Foreign reboot schedule active: '+', '.join(conflicts)+'; nothing changed')
                desired = {'version': 1, 'enabled': True, 'time': schedule_time, 'timezone': timezone}
            else:
                desired = dict(original, enabled=False)
            backup, record = self.backup(previous)
            try:
                atomic_write(self.path(CONFIG), json.dumps(desired).encode(), 0o600)
                if enabled:
                    unit = (HEADER+'[Unit]\nDescription=X-Manager daily reboot timer\n\n[Timer]\nOnCalendar='+value+
                            '\nPersistent=false\nRandomizedDelaySec=600\nUnit='+SERVICE+'\n\n[Install]\nWantedBy=timers.target\n')
                    atomic_write(timer_file, unit.encode(), 0o644)
                    self.ctl('daemon-reload')
                    if previous.get('UnitFileState') == 'enabled-runtime':
                        self.ctl('enable', '--runtime', TIMER)
                    else:
                        self.ctl('enable', TIMER)
                    self.ctl('restart', TIMER)
                    if self.show().get('ActiveState') != 'active':
                        raise RuntimeError('Reboot timer did not become active')
                else:
                    if previous.get('LoadState') == 'loaded':
                        self.ctl('stop', TIMER)
                        if previous.get('UnitFileState') == 'enabled-runtime':
                            self.ctl('disable', '--runtime', TIMER)
                        self.ctl('disable', TIMER)
            except Exception as error:
                try:
                    self.restore(backup, record)
                except Exception as rollback:
                    raise RuntimeError('Schedule change and rollback failed. Keep backup '+str(backup)) from rollback
                raise RuntimeError('Schedule change failed; original state restored. Backup: '+str(backup)) from error
            return {'changed': True, 'enabled': enabled, 'backup': str(backup)}

    def status(self):
        data = self.read()
        current = self.show()
        return dict(data, active=current.get('ActiveState'), autostart=current.get('UnitFileState'),
                    next_trigger=current.get('NextElapseUSecRealtime') or None,
                    conflicts=self.foreign_conflicts())

    def run_due(self, environment=None, now=None, pid=None):
        """No waiting: a maintenance collision skips this occurrence completely."""
        environment = os.environ if environment is None else environment
        if not re.fullmatch(r'[0-9a-fA-F]{32}', environment.get('INVOCATION_ID', '')):
            return {'reboot': False, 'reason': 'Only a systemd timer invocation may request a reboot'}
        with self.lock(INSTALL_LOCK) as install:
            if not install:
                return {'reboot': False, 'reason': 'Installation or rollback in progress; occurrence skipped'}
            with self.lock() as acquired:
                if not acquired:
                    return {'reboot': False, 'reason': 'Schedule update in progress; occurrence skipped'}
                if self.path(MAINTENANCE).exists():
                    return {'reboot': False, 'reason': 'Unfinished maintenance; occurrence skipped'}
                data = self.read()
                if not data['enabled']:
                    return {'reboot': False, 'reason': 'Scheduled reboot disabled'}
                timer = self.show()
                service = self.show(SERVICE)
                if (timer.get('ActiveState') != 'active'
                        or timer.get('UnitFileState') not in ('enabled', 'enabled-runtime')
                        or service.get('MainPID') != str(os.getpid() if pid is None else pid)):
                    return {'reboot': False, 'reason': 'Not an enabled timer service invocation'}
                last = timer.get('LastTriggerUSecMonotonic', '0')
                elapsed = (time.monotonic() if now is None else now)*1_000_000
                if not last.isdigit() or int(last) == 0 or not 0 <= elapsed-int(last) <= 60_000_000:
                    return {'reboot': False, 'reason': 'No current timer event; late/manual occurrence skipped'}
                if self.foreign_conflicts():
                    return {'reboot': False, 'reason': 'Foreign reboot schedule active; occurrence skipped'}
                self.ctl('reboot')
                return {'reboot': True, 'reason': 'Configured daily timer'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('bootstrap', 'configure', 'disable', 'status', 'run'))
    parser.add_argument('--time')
    parser.add_argument('--timezone')
    parser.add_argument('--disabled', action='store_true')
    parser.add_argument('--human', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root')
    if (args.time or args.timezone or args.disabled) and args.action != 'configure':
        parser.error('Schedule options apply only to configure')
    scheduler = Scheduler()
    try:
        if args.action == 'configure':
            if args.disabled and (args.time or args.timezone):
                parser.error('--disabled cannot be combined with --time/--timezone')
            result = scheduler.configure(args.time, args.timezone, enabled=not args.disabled)
        elif args.action == 'disable':
            result = scheduler.configure(enabled=False)
        elif args.action == 'run':
            result = scheduler.run_due()
        else:
            result = getattr(scheduler, args.action)()
        if args.human:
            status = scheduler.status()
            print('Ежедневная перезагрузка: '+('включена' if status['enabled'] else 'выключена'))
            if status.get('time'):
                print('Расписание: '+status['time']+' '+status['timezone']+'; задержка до 10 минут')
            print('Следующий запуск: '+str(status['next_trigger'] or 'не назначен'))
            print('Таймер: '+str(status['active'])+'; автозапуск: '+str(status['autostart']))
            if status['conflicts']:
                print('Конфликт с внешним расписанием: '+', '.join(status['conflicts']))
        else:
            print(json.dumps(result, ensure_ascii=False))
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))


if __name__ == '__main__':
    main()
