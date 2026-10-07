#!/usr/bin/env python3
"""Bounded crash recovery using systemd; no polling, no restart after manual stop."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

UNITS=['tuna-subscriptions','webdav-tunnel','snell','mita','wdtt','csqtt','masterdns','cottendns','x-ui','xray']+['openflux@'+str(i) for i in range(1,9)]+['snell6@'+str(i) for i in range(1,9)]
ROOT=Path('/etc/systemd/system')
BACKUPS=Path('/var/backups')
ENDPOINTS=Path('/etc/snell6/endpoints')
NAME='90-tuna-watchdog.conf'

def lifecycle():
    # Both the checkout and the installed share directory keep these siblings.
    spec=importlib.util.spec_from_file_location('tuna_service_control',Path(__file__).with_name('service-control.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.Controller()

def openflux_watchdog():
    spec=importlib.util.spec_from_file_location('openflux_watchdog',Path(__file__).with_name('openflux-watchdog.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.Watchdog()


def openflux_menu():
    group=openflux_watchdog()
    while True:
        state=group.status()
        print('\nOpenFlux — общий бюджет всех каналов')
        if state['configured']:
            print(f"Лимит: {state['attempts']}\nИспользовано: {state['spent']}\nОсталось: {state['remaining']}\nПауза: {state['delay']} с")
        else:print('Общий бюджет ещё не настроен.')
        print('Перезапускается только упавший канал. Ручной stop/off сохраняется.')
        action=input('[1] Настроить общий лимит\n[2] Выключить автоперезапуск OpenFlux\n[3] Сбросить общий счётчик\n[0] Назад\nДействие: ').strip()
        if action=='0':return
        if action=='1':
            count=int(input('Общее число попыток [Enter=20]: ').strip() or '20')
            delay=int(input('Пауза, секунд [Enter=30]: ').strip() or '30')
            group.configure(count,delay)
            print('Общий лимит сохранён. Работающие каналы не перезапускались.')
        elif action=='2':
            group.configure(0,state.get('delay',10))
            print('Автоматические перезапуски OpenFlux выключены. Каналы не остановлены.')
        elif action=='3':
            if input('Разрешить новый общий бюджет попыток? [1] Да [0] Назад: ').strip()=='1':
                group.reset()
                print('Общий счётчик сброшен. Каналы не запускались; запуск — в управлении службами.')


def ctl(*args):return subprocess.check_output(['systemctl',*args],text=True).strip()
def show(unit):
    return dict(l.split('=',1) for l in ctl('show',unit,'-p','LoadState','-p','ActiveState','-p','UnitFileState','-p','DropInPaths','-p','Type','-p','Restart','-p','RestartUSec','-p','StartLimitBurst','-p','StartLimitIntervalUSec','-p','Result','-p','NRestarts').splitlines() if '=' in l)
def render(attempts,delay):
    if not 0<=attempts<=20 or not 1<=delay<=3600:raise ValueError('Лимит 0–20, задержка 1–3600 секунд')
    return ('# Managed by TUNA watchdog; reset limit explicitly from the menu.\n[Unit]\n'
            'StartLimitIntervalSec=infinity\nStartLimitBurst='+str(attempts+1)+'\n[Service]\n'
            'Restart='+('on-failure' if attempts else 'no')+'\nRestartSec='+str(delay)+'s\n')
def apply(unit,attempts,delay):
    if unit.startswith('openflux@'):
        raise ValueError('Для OpenFlux настройте общий лимит через раздел OpenFlux')
    if unit not in UNITS:raise ValueError('Выберите службу из списка X-Manager')
    if lifecycle().status(unit)['off']:
        raise ValueError('Служба постоянно выключена; сначала включите её в управлении службами')
    state=show(unit)
    if state['LoadState']!='loaded' or state['Type']=='oneshot':raise ValueError('Нужна установленная постоянная служба')
    data=render(attempts,delay)
    directory=ROOT/(unit+'.service.d');directory.mkdir(exist_ok=True)
    path=directory/NAME
    backup=Path(tempfile.mkdtemp(prefix='tuna-watchdog-',dir='/var/backups'))
    old=path.read_bytes() if path.exists() else None
    if old is not None:(backup/NAME).write_bytes(old)
    (backup/'state.json').write_text(json.dumps({'path':str(path),'existed':old is not None}))
    tmp=directory/('.'+NAME+'.new');tmp.write_text(data);tmp.chmod(0o644);os.replace(tmp,path)
    try:
        ctl('daemon-reload')
        state=show(unit)
        if state['Restart']!=('on-failure' if attempts else 'no') or int(state['StartLimitBurst'])!=attempts+1 or state['StartLimitIntervalUSec']!='infinity':
            raise ValueError('Другой systemd override перекрывает выбранный лимит')
    except BaseException:
        if old is None:path.unlink()
        else:path.write_bytes(old)
        ctl('daemon-reload');raise
    print(unit+': политика сохранена, работающая служба не перезапущена. Копия: '+str(backup))

def retire_legacy(attempts, delay):
    # Installer-only transition after the managed snapshot, with explicit opt-in.
    if os.environ.get('XM_WATCHDOG_TRANSACTION') != '1':
        raise ValueError('Legacy migration requires the installer backup transaction')
    render(attempts, delay)
    active = []
    for unit in UNITS:
        state = show(unit)
        if state.get('LoadState') == 'loaded' and state.get('ActiveState') == 'active' and state.get('Type') != 'oneshot' and lifecycle().allowed(unit):
            active.append(unit)
    for unit in ('tuna-watchdog.timer', 'tuna-watchdog.service'):
        if show(unit).get('LoadState') == 'loaded':
            ctl('stop', unit)
            if subprocess.run(['systemctl','is-enabled','--quiet',unit]).returncode == 0:
                ctl('disable', unit)
    for unit in active:
        if not unit.startswith("openflux@"):
            apply(unit, attempts, delay)
    if any(unit.startswith("openflux@") for unit in active):
        openflux_watchdog().configure(attempts, delay)
    print('Legacy watchdog stopped; bounded policies applied without restarting running services.')


def check_default_conflicts(controller):
    # Check before taking the lifecycle lock, which itself creates a file.
    for state in controller.conflicts():
        if state.get('conflict') or state.get('ActiveState') == 'deactivating':
            raise ValueError('Конфликт внешнего watchdog: '+state['unit']+'; сначала явно остановите его')


def default_skip(unit, state, intent):
    if not endpoint_present(unit):
        return 'no-endpoint'
    if state.get('LoadState') == 'masked' or state.get('UnitFileState', '').startswith('masked'):
        return 'masked'
    if state.get('LoadState') != 'loaded':
        return 'not-installed'
    if state.get('Type') == 'oneshot':
        return 'oneshot'
    if intent['off']:
        return 'off'
    directory = ROOT/(unit+'.service.d')
    if directory.is_symlink():
        return 'custom-dropin-directory'
    # Include effective vendor/runtime/template drop-ins, plus pending local
    # files not yet seen by systemd. Never overwrite a user's restart policy.
    paths = set(directory.glob('*.conf'))
    paths.update((ROOT/'service.d').glob('*.conf'))
    if '@' in unit:
        paths.update((ROOT/(unit.split('@')[0]+'@.service.d')).glob('*.conf'))
    for token in state.get('DropInPaths', '').split():
        decoded = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m[1], 16)), token)
        paths.add(Path(decoded))
    for path in sorted(paths):
        if path.name == NAME:
            return 'existing-policy'
        if path.is_symlink():
            return 'custom-dropin'
        content = path.read_text(encoding='utf-8')
        if re.search(r'^\s*(?:Restart\w*|StartLimit\w*)\s*=', content, re.MULTILINE):
            return 'custom-restart-policy'
    # A broken symlink is not included by every filesystem's glob.
    if (directory/NAME).exists() or (directory/NAME).is_symlink():
        return 'existing-policy'
    return None


def endpoint_present(unit):
    return not unit.startswith('snell6@') or (ENDPOINTS/unit.split('@')[1]/'endpoint.json').is_file()


def verify_default(unit, attempts, delay):
    state = show(unit)
    # systemctl formats seconds as composite durations once delay exceeds 60s.
    parts = re.findall(r'(\d+(?:\.\d+)?)(us|ms|min|h|s)', state.get('RestartUSec', '').replace(' ', ''))
    seconds = sum(float(value)*{'us': .000001, 'ms': .001, 's': 1, 'min': 60, 'h': 3600}[suffix]
                  for value, suffix in parts)
    if (state.get('Restart') != ('on-failure' if attempts else 'no')
            or state.get('StartLimitBurst') != str(attempts+1)
            or state.get('StartLimitIntervalUSec') != 'infinity'
            or not parts or abs(seconds-delay) > .000001):
        raise ValueError('Не подтверждена политика systemd для '+unit)


def defaults(attempts=5, delay=30):
    """Add missing crash policies as one transaction; never activate a unit."""
    data = render(attempts, delay)
    controller = lifecycle()
    check_default_conflicts(controller)
    with controller.lock():
        check_default_conflicts(controller)
        changed, skipped, plan = [], [], []
        for unit in UNITS:
            if unit.startswith('openflux@'):continue
            state = show(unit)
            intent = controller.status(unit)
            reason = default_skip(unit, state, intent)
            if reason:
                skipped.append({'unit': unit, 'reason': reason})
            else:
                plan.append(unit)
        result = {'changed': changed, 'skipped': skipped, 'attempts': attempts, 'delay': delay, 'backup': None}
        if not plan:
            return result
        # Preflight completes before creating the backup or any policy file.
        check_default_conflicts(controller)
        backup = Path(tempfile.mkdtemp(prefix='tuna-watchdog-defaults-', dir=BACKUPS))
        result['backup'] = str(backup)
        records = [{'unit': unit, 'path': str(ROOT/(unit+'.service.d')/NAME), 'existed': False}
                   for unit in plan]
        (backup/'state.json').write_text(json.dumps({'files': records}, indent=2)+'\n', encoding='utf-8')
        written, directories = [], []
        try:
            for record in records:
                path = Path(record['path'])
                if not path.parent.exists():
                    path.parent.mkdir()
                    directories.append(path.parent)
                # Exclusive creation also preserves an unexpected concurrent edit.
                with path.open('x', encoding='utf-8', newline='\n') as stream:
                    written.append(path)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                path.chmod(0o644)
            ctl('daemon-reload')
            for unit in plan:
                verify_default(unit, attempts, delay)
            changed.extend(plan)
        except BaseException:
            for path in reversed(written):
                path.unlink()
            for directory in reversed(directories):
                directory.rmdir()
            ctl('daemon-reload')
            raise
        return result


def menu():
    while True:
        controller=lifecycle()
        available=[]
        print('\nTUNA Watchdog — аварийный перезапуск служб')
        print('Для настроенных политик после лимита запуск блокируется до ручного сброса. Штатный stop не вызывает перезапуск.')
        print('OpenFlux: общий бюджет автоперезапусков, сохраняется после перезагрузки.')
        print('Остальные службы: лимит systemd учитывает ручные старты и сбрасывается при перезагрузке.')
        for conflict in controller.conflicts():
            if conflict['conflict']:
                print('Конфликт владельцев перезапуска: '+conflict['unit']+'. Выберите watchdog в управлении службами; автоматического отключения нет.')
        group_shown=False
        for unit in UNITS:
            if unit.startswith('openflux@'):
                if not group_shown and show(unit).get('LoadState')=='loaded':
                    group_shown=True
                    available.append('openflux')
                    state=openflux_watchdog().status()
                    active=sum(show('openflux@'+str(i)).get('ActiveState')=='active' for i in range(1,9))
                    description=(f"общий лимит {state['attempts']}; использовано {state['spent']}; осталось {state['remaining']}" if state['configured'] else 'общий бюджет ещё не настроен')
                    print(f'[{len(available)}] OpenFlux: работает каналов {active}; {description}')
                continue
            if not endpoint_present(unit):continue
            state=show(unit)
            if state.get('LoadState')!='loaded' or state.get('Type')=='oneshot':continue
            available.append(unit)
            managed=(ROOT/(unit+'.service.d')/NAME).exists()
            policy=('лимит '+str(max(0,int(state['StartLimitBurst'])-1))+', '+state['Restart']) if managed else ('штатная: Restart='+state['Restart']+', задержка='+state.get('RestartUSec','?')+', StartLimit='+state.get('StartLimitBurst','?')+'/'+state.get('StartLimitIntervalUSec','?'))
            intent=controller.status(unit)
            inhibit='; постоянно выключена' if intent['off'] else '; ручной стоп' if intent['stopped'] else ''
            print(f'[{len(available)}] {unit}: {state["ActiveState"]}; {policy}; результат {state.get("Result")}; рестартов {state.get("NRestarts")}{inhibit}')
        pick=input('[0] Назад\nСлужба: ').strip()
        if pick=='0':return
        if not pick.isdigit() or not 1<=int(pick)<=len(available):continue
        unit=available[int(pick)-1]
        if unit=='openflux':
            openflux_menu()
            continue
        action=input('[1] Настроить лимит\n[2] Отключить автоперезапуск\n[3] Сбросить лимит и запустить\n[4] Логи\n[0] Назад\nДействие: ').strip()
        if action=='1':
            count=input('Число повторных попыток [1–20, Enter=5]: ').strip() or '5'
            delay=input('Пауза в секундах [1–3600, Enter=30]: ').strip() or '30'
            apply(unit,int(count),int(delay))
        elif action=='2':apply(unit,0,30)
        elif action=='3':
            print('Состояние:',controller.change('start',unit)['ActiveState'])
        elif action=='4':subprocess.run(['journalctl','-u',unit,'-n','30','--no-pager'],check=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['menu','set','retire-legacy','defaults']);parser.add_argument('--unit');parser.add_argument('--attempts',type=int,default=5);parser.add_argument('--delay',type=int);parser.add_argument('--json',action='store_true')
    a=parser.parse_args()
    if a.delay is None:a.delay=30
    if a.action=='menu':menu()
    elif a.action=='defaults':
        result=defaults(a.attempts,a.delay)
        group=openflux_watchdog()
        state=group.status()
        grouped=group.configure(state['attempts'] if state['configured'] else 20,
                                state['delay'] if state['configured'] else 30)
        if not a.json:print('OpenFlux: общий бюджет сохранён.' if state['configured'] else 'OpenFlux: настройка общего бюджета завершена.')
        result['openflux']=grouped
        if a.json:print(json.dumps(result,ensure_ascii=False))
        else:
            print('Базовая защита настроена для: '+', '.join(result['changed']) if result['changed'] else 'Базовая защита: новые политики не требуются.')
            reasons = {'existing-policy':'настройки уже сохранены', 'off':'выключена пользователем',
                       'masked':'запуск заблокирован пользователем', 'custom-restart-policy':'сохранены пользовательские настройки',
                       'custom-dropin':'сохранена сторонняя конфигурация', 'custom-dropin-directory':'сохранена сторонняя конфигурация'}
            for item in result['skipped']:
                if item['reason'] in ('not-installed','no-endpoint','oneshot'):continue
                print(item['unit']+': '+reasons.get(item['reason'],'сохранена существующая конфигурация'))
            if result['backup']:print('Копия: '+result['backup'])
    elif a.action=='retire-legacy':retire_legacy(a.attempts,a.delay)
    else:apply(a.unit,a.attempts,a.delay)
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,RuntimeError,subprocess.CalledProcessError) as e:
        print('Ошибка Watchdog:',e);raise SystemExit(1)
    except (EOFError,KeyboardInterrupt):pass
