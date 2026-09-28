#!/usr/bin/env python3
"""Bounded crash recovery using systemd; no polling, no restart after manual stop."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

UNITS=['tuna-subscriptions','webdav-tunnel','snell','mita','wdtt','csqtt','masterdns','cottendns']+['openflux@'+str(i) for i in range(1,9)]
ROOT=Path('/etc/systemd/system')
NAME='90-tuna-watchdog.conf'

def ctl(*args):return subprocess.check_output(['systemctl',*args],text=True).strip()
def show(unit):
    return dict(l.split('=',1) for l in ctl('show',unit,'-p','LoadState','-p','ActiveState','-p','Type','-p','Restart','-p','RestartUSec','-p','StartLimitBurst','-p','StartLimitIntervalUSec','-p','Result','-p','NRestarts').splitlines() if '=' in l)
def render(attempts,delay):
    if not 0<=attempts<=20 or not 1<=delay<=3600:raise ValueError('Лимит 0–20, задержка 1–3600 секунд')
    return ('# Managed by TUNA watchdog; reset limit explicitly from the menu.\n[Unit]\n'
            'StartLimitIntervalSec=infinity\nStartLimitBurst='+str(attempts+1)+'\n[Service]\n'
            'Restart='+('on-failure' if attempts else 'no')+'\nRestartSec='+str(delay)+'s\n')
def apply(unit,attempts,delay):
    if unit not in UNITS:raise ValueError('Выберите службу из списка X-Manager')
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

def menu():
    while True:
        available=[]
        print('\nTUNA Watchdog — аварийный перезапуск служб')
        print('После лимита запуск блокируется до ручного сброса. Штатный stop не вызывает перезапуск.')
        print('Лимит учитывает старты systemd, включая ручные; перезагрузка VPS сбрасывает счётчик.')
        for unit in UNITS:
            state=show(unit)
            if state.get('LoadState')!='loaded' or state.get('Type')=='oneshot':continue
            available.append(unit)
            managed=(ROOT/(unit+'.service.d')/NAME).exists()
            policy=('лимит '+str(max(0,int(state['StartLimitBurst'])-1))+', '+state['Restart']) if managed else 'штатная политика'
            print(f'[{len(available)}] {unit}: {state["ActiveState"]}; {policy}; результат {state.get("Result")}; рестартов {state.get("NRestarts")}')
        pick=input('[0] Назад\nСлужба: ').strip()
        if pick=='0':return
        if not pick.isdigit() or not 1<=int(pick)<=len(available):continue
        unit=available[int(pick)-1]
        action=input('[1] Настроить лимит\n[2] Отключить автоперезапуск\n[3] Сбросить лимит и запустить\n[4] Логи\n[0] Назад\nДействие: ').strip()
        if action=='1':
            count=input('Число повторных попыток [1–20, Enter=3]: ').strip() or '3'
            delay=input('Пауза в секундах [1–3600, Enter=30]: ').strip() or '30'
            apply(unit,int(count),int(delay))
        elif action=='2':apply(unit,0,30)
        elif action=='3':
            ctl('reset-failed',unit);ctl('start',unit)
            print('Состояние:',show(unit)['ActiveState'])
        elif action=='4':subprocess.run(['journalctl','-u',unit,'-n','30','--no-pager'],check=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['menu','set']);parser.add_argument('--unit');parser.add_argument('--attempts',type=int,default=3);parser.add_argument('--delay',type=int,default=30)
    a=parser.parse_args()
    if a.action=='menu':menu()
    else:apply(a.unit,a.attempts,a.delay)
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.CalledProcessError) as e:
        print('Ошибка Watchdog:',e);raise SystemExit(1)
    except (EOFError,KeyboardInterrupt):pass
