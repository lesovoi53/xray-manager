#!/usr/bin/env python3
"""Manage only tagged WebDAV INPUT rules; never flush shared firewall tables."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path('/etc/webdav-tunnel')
MARK = 'XM_WEBDAV_ACCESS'


def local_port(root=ROOT):
    path = root/'config.env'
    if not path.is_file():
        return None
    env = {}
    for line in path.read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            if key.strip() not in ('WEBDAV_MODE', 'MULTI_LOCAL_ENABLED', 'WEBDAV_LISTEN', 'SELFHOSTED_PORT'):
                continue
            values = shlex.split(value, comments=True)
            if len(values) > 1:
                raise ValueError('Некорректная конфигурация WebDAV')
            env[key.strip()] = values[0] if values else ''
    mode = env.get('WEBDAV_MODE', 'selfhosted')
    if mode in ('mailru', 'yandex', 'custom', 'server', 'external'):
        return None
    if mode == 'multi' and env.get('MULTI_LOCAL_ENABLED', 'true') != 'true':
        return None
    if mode not in ('selfhosted', 'multi'):
        raise ValueError('Неизвестный режим WebDAV')
    listen = env.get('WEBDAV_LISTEN', '')
    raw = listen.rsplit(':', 1)[-1] if listen else env.get('SELFHOSTED_PORT', '18080')
    if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= 65535 or int(raw) in (443, 8443):
        raise ValueError('Недопустимый локальный порт WebDAV; настройки не изменены')
    return int(raw)


def rule(port, state):
    return ['-A', 'INPUT', '!', '-i', 'lo', '-p', 'tcp', '-m', 'tcp', '--dport', str(port),
            '-m', 'comment', '--comment', MARK, '-j', 'DROP' if state == 'blocked' else 'ACCEPT']


class Firewall:
    families = ('iptables', 'ip6tables')

    def __init__(self):
        self.first = {}

    def read(self, family):
        output = subprocess.check_output([family, '-w', '5', '-S', 'INPUT'], text=True)
        owned = []
        rules = [shlex.split(line) for line in output.splitlines() if line.startswith('-A INPUT ')]
        self.first[family] = rules[0] if rules else None
        for line in output.splitlines():
            tokens = shlex.split(line)
            if '--comment' not in tokens or tokens[tokens.index('--comment')+1] != MARK:
                continue
            try:
                port = int(tokens[tokens.index('--dport')+1])
                state = {'DROP': 'blocked', 'ACCEPT': 'open'}[tokens[-1]]
            except (ValueError, KeyError, IndexError):
                raise ValueError('Неизвестное правило с меткой WebDAV; требуется проверка')
            if tokens != rule(port, state):
                raise ValueError('Конфликт метки WebDAV; чужое правило не изменено')
            owned.append(tokens)
        return owned

    @staticmethod
    def plan(old, new):
        lines = [['-D']+r[1:] for r in old]
        lines += [['-I', 'INPUT', '1']+r[2:] for r in reversed(new)]
        return '*filter\n'+'\n'.join(' '.join(r) for r in lines)+'\nCOMMIT\n'

    def apply(self, family, old, new, test=False):
        args = [family+'-restore', '-w', '5', '--noflush']
        if test:
            args.append('--test')
        subprocess.run(args, input=self.plan(old, new), text=True, check=True)


def read_policy(root):
    path = root/'access-policy.json'
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    if data not in ({'state': 'blocked'}, {'state': 'open'}):
        raise ValueError('Некорректная политика доступа WebDAV')
    return data['state']


def save_policy(root, state):
    fd, name = tempfile.mkstemp(prefix='.access-', dir=root)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump({'state': state}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, root/'access-policy.json')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def change(action, root=ROOT, firewall=None, if_local=False):
    port = local_port(root)
    if action != 'sync' and port is None:
        if if_local:
            return
        raise ValueError('Локальный WebDAV не включён: у облачного режима нет входящего порта')
    saved = read_policy(root)
    state = saved if action == 'sync' else action
    if state is None:
        return  # Preserve existing installation until the user chooses a policy.
    fw = firewall or Firewall()
    wanted = [rule(port, state)] if port is not None else []
    before = {family: fw.read(family) for family in fw.families}
    changes = [family for family in fw.families if before[family] != wanted or (wanted and fw.first.get(family) != wanted[0])]
    if not changes and state == saved:
        return
    for family in changes:
        fw.apply(family, before[family], wanted, test=True)
    directory = root/'access-backups'
    directory.mkdir(mode=0o700, exist_ok=True)
    fd, backup = tempfile.mkstemp(prefix='policy-', suffix='.json', dir=directory)
    with os.fdopen(fd, 'w') as f:
        json.dump({'policy': saved, 'rules': before}, f)
    try:
        for family in changes:
            fw.apply(family, before[family], wanted)
        for family in fw.families:
            if fw.read(family) != wanted or (wanted and fw.first.get(family) != wanted[0]):
                raise RuntimeError('Проверка правил WebDAV после применения не прошла')
        if action != 'sync':
            save_policy(root, state)
    except Exception:
        for family in fw.families:
            current = fw.read(family)
            if current != before[family]:
                fw.apply(family, current, before[family])
        raise
    print('Политика WebDAV применена; резервная копия:', backup)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('menu', 'blocked', 'open', 'sync'))
    parser.add_argument('--if-local', action='store_true')
    args = parser.parse_args()
    action = args.action
    if action == 'menu':
        port = local_port()
        if port is None:
            print('Локальный WebDAV не включён. Облачный режим не имеет входящего порта.')
            input('Enter — назад: ')
            return
        policy = read_policy(ROOT)
        print('WebDAV: TCP/%d. Управление внешним доступом IPv4 и IPv6; loopback сохраняется.' % port)
        print('Сохранённая политика:', {'blocked': 'закрыт', 'open': 'открыт', None: 'не задана'}[policy])
        if policy is not None:
            fw = Firewall()
            print('Правила:', 'соответствуют политике' if all(fw.read(f) == [rule(port, policy)] and fw.first.get(f) == rule(port, policy) for f in fw.families) else 'отличаются; примените выбранное действие')
        print('[1] Закрыть внешний доступ\n[2] Открыть внешний доступ\n[0] Назад')
        choice = input('Действие: ').strip()
        if choice == '0':
            return
        if choice not in ('1', '2'):
            raise ValueError('Выберите 0, 1 или 2')
        action = 'blocked' if choice == '1' else 'open'
    if not (ROOT/'config.env').is_file() and action == 'sync':
        return
    if not (ROOT/'config.env').is_file() and args.if_local:
        return
    with (ROOT/'.access.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        change(action, if_local=args.if_local)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print('Ошибка доступа WebDAV:', error, file=__import__('sys').stderr)
        raise SystemExit(1)
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(1)
