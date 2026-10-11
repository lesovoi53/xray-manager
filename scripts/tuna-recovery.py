#!/usr/bin/env python3
"""Resume only managed crash-limit failures after five minutes; never normal stops."""
import fcntl
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import time
import re

STATE = '/var/lib/x-manager/recovery/state.json'
HEADER = '# Managed by TUNA watchdog; automatic reset after 300s via tuna-recovery.timer.\n'


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class Recovery:
    def __init__(self, root='/', watchdog=None, now=time.time):
        self.root = Path(root)
        self.watchdog = watchdog or module('tuna-watchdog')
        self.now = now

    def path(self, value):
        p = self.root/value.lstrip('/')
        current = p
        while current != self.root:
            if current.is_symlink():
                raise ValueError('Символическая ссылка вместо состояния восстановления')
            current = current.parent
        return p

    def save(self, records):
        p = self.path(STATE)
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(dir=p.parent, prefix='.state-')
        try:
            with os.fdopen(fd, 'w') as out:
                json.dump(records, out); out.flush(); os.fsync(out.fileno())
            os.replace(name, p)
        finally:
            if os.path.exists(name): os.unlink(name)

    def tick(self):
        p = self.path(STATE)
        if p.exists() and p.stat().st_size > 65536:
            raise ValueError('Слишком большой файл состояния восстановления')
        records = json.loads(p.read_text()) if p.exists() else {}
        if not isinstance(records, dict) or any(k not in self.watchdog.UNITS or type(v) not in (int,float) or not math.isfinite(v) or v < 0 for k,v in records.items()):
            raise ValueError('Некорректный счётчик восстановления; файл сохранён')
        controller = self.watchdog.lifecycle()
        if any(r.get('conflict') or r.get('ActiveState') == 'deactivating' for r in controller.conflicts()):
            return
        with controller.lock():
            for unit in self.watchdog.UNITS:
                if unit.startswith('openflux@'): continue
                policy = self.path('/etc/systemd/system/'+unit+'.service.d/90-tuna-watchdog.conf')
                text = policy.read_text() if policy.is_file() else ''
                live = self.watchdog.show(unit)
                # Debian 13/systemd can retain the last process failure result
                # after rejecting the next restart at StartLimitBurst.
                burst, restarts = live.get('StartLimitBurst', ''), live.get('NRestarts', '')
                exhausted = (live.get('Result') == 'start-limit-hit' or
                             (burst.isdigit() and restarts.isdigit() and int(burst) > 0
                              and int(restarts) >= int(burst)
                              and live.get('Restart') == 'on-failure'
                              and live.get('StartLimitIntervalUSec') == 'infinity'))
                owned = re.fullmatch(re.escape(HEADER) +
                    r'\[Unit\]\nStartLimitIntervalSec=infinity\nStartLimitBurst=(?:[2-9]|1[0-9]|2[01])\n'
                    r'\[Service\]\nRestart=on-failure\nRestartSec=[0-9]+s\n', text) is not None
                eligible = (owned
                            and controller.allowed(unit) and live.get('LoadState') == 'loaded'
                            and not live.get('UnitFileState','').startswith('masked')
                            and live.get('ActiveState') == 'failed' and exhausted)
                if not eligible:
                    records.pop(unit, None)
                    continue
                now = self.now()
                since = records.setdefault(unit, now)
                if now < since: records[unit] = now
                elif now-since >= 300:
                    # Persist before commands: interrupted/rejected recovery cannot busy-loop.
                    records[unit] = now
                    self.save(records)
                    self.watchdog.ctl('reset-failed', unit)
                    self.watchdog.ctl('start', '--no-block', unit)
                    print(unit+': пять минут истекли, счётчик сброшен; запуск запрошен')
            self.save(records)


def main():
    if os.geteuid() != 0: raise ValueError('Требуются права root')
    with open('/run/lock/x-manager-install.lock','a') as install, open('/run/lock/tuna-recovery.lock','a') as worker:
        try:
            fcntl.flock(install, fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(worker, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if Path('/var/lib/x-manager/maintenance-watchdog.json').exists(): return
        Recovery().tick()
        module('openflux-watchdog').Watchdog().recover()


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit('Ошибка восстановления: '+str(error))
