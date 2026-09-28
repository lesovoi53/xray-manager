#!/usr/bin/env python3
"""Volga preflight, private cookie import and transactional channel configuration."""
import argparse
import grp
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

COOKIE = Path('/etc/openflux/yandex-cookies.txt')
CHECK = '/usr/local/bin/openflux-volga-check'

def load_jar(path):
    jar=http.cookiejar.MozillaCookieJar(str(path))
    jar.load(ignore_discard=True,ignore_expires=True)
    for c in list(jar):
        if c.expires==0:
            c.expires=None;c.discard=True
        elif c.is_expired():jar.clear(c.domain,c.path,c.name)
    return jar

def validate(text, mode='multistream'):
    urls = [v.strip() for v in text.strip().split(',')]
    if not 1 <= len(urls) <= (4 if mode == 'multistream' else 1):
        raise ValueError('Нужно 1–4 документа в Multi-Stream или один в Classic')
    if len(set(urls)) != len(urls):
        raise ValueError('Документы не должны повторяться')
    for u in urls:
        p = urlsplit(u)
        if (len(u.encode()) > 8192 or p.scheme != 'https' or p.hostname not in ('disk.yandex.ru','docs.yandex.ru')
                or p.username or p.password or p.port not in (None,443) or p.path in ('','/')
                or any(c.isspace() or ord(c)<32 or c in '\"\'`$\\' for c in u)):
            raise ValueError('Нужна HTTPS-ссылка документа disk.yandex.ru или docs.yandex.ru без небезопасных символов')
    return ','.join(urls)

def preflight(path):
    validate(Path(path).read_text())
    cmd=[CHECK,'--url-file='+str(path)]
    if COOKIE.exists(): cmd.append('--cookies-file='+str(COOKIE))
    subprocess.run(cmd,check=True,timeout=260)

def cookies(path):
    source=Path(path)
    if source.stat().st_size>1048576: raise ValueError('Cookies file exceeds 1 MiB')
    jar=load_jar(source)
    filtered=[c for c in jar if c.domain.lstrip('.')=='yandex.ru' or c.domain.endswith('.yandex.ru')]
    if not filtered: raise ValueError('В файле нет действующих cookies Яндекса')
    target=http.cookiejar.MozillaCookieJar()
    for c in filtered: target.set_cookie(c)
    COOKIE.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix='.yandex-cookies-',dir=COOKIE.parent);os.close(fd)
    try:
        target.save(tmp,ignore_discard=True,ignore_expires=False)
        os.chown(tmp,0,grp.getgrnam('openflux').gr_gid);os.chmod(tmp,0o640)
        if COOKIE.exists():
            backup=Path(tempfile.mkdtemp(prefix='volga-cookies-',dir='/var/backups'))
            shutil.copy2(COOKIE,backup/'yandex-cookies.txt')
        os.replace(tmp,COOKIE)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    print('Cookies Яндекса сохранены в закрытом файле; действующие каналы не перезапущены.')

def refresh():
    """Renew server-issued cookies using the saved session; never solve CAPTCHA."""
    jar=load_jar(COOKIE) if COOKIE.exists() else http.cookiejar.MozillaCookieJar(str(COOKIE))
    docs=[]
    for file in sorted(Path('/etc/openflux/instances').glob('[1-8].env')):
        props={k:v.strip().strip('"').strip("'") for k,v in (l.split('=',1) for l in file.read_text().splitlines() if '=' in l)}
        if props.get('TRANSPORT')=='vyandex' and props.get('URL'):
            docs.extend(validate(props['URL']).split(','))
    docs=list(dict.fromkeys(docs))
    if not docs:raise ValueError('Нет настроенных каналов Волги')
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    for url in docs:
        request=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'})
        with opener.open(request,timeout=30) as response:
            body=response.read(4194305)
            host=urlsplit(response.url).hostname or ''
        if len(body)>4194304:raise ValueError('Ответ документа слишком большой')
        if host not in ('disk.yandex.ru','docs.yandex.ru') or b'action_url' not in body:
            raise ValueError('Нужно ручное открытие документа/SmartCaptcha с IP VPS. Прежние cookies сохранены')
    filtered=http.cookiejar.MozillaCookieJar()
    for c in jar:
        if c.domain.lstrip('.')=='yandex.ru' or c.domain.endswith('.yandex.ru'):filtered.set_cookie(c)
    fd,candidate=tempfile.mkstemp(prefix='.volga-cookies-',dir=COOKIE.parent);os.close(fd)
    fd,docfile=tempfile.mkstemp(prefix='.volga-check-',dir=COOKIE.parent);os.close(fd)
    try:
        filtered.save(candidate,ignore_discard=True,ignore_expires=False)
        # Verify all configured documents before replacing the last working file.
        for url in docs:
            Path(docfile).write_text(url)
            subprocess.run([CHECK,'--url-file='+docfile,'--cookies-file='+candidate],check=True,timeout=70,stdout=subprocess.DEVNULL)
        if COOKIE.exists():
            old=COOKIE.with_name('yandex-cookies.previous.txt')
            fd,tmp=tempfile.mkstemp(prefix='.cookies-backup-',dir=COOKIE.parent);os.close(fd)
            shutil.copyfile(COOKIE,tmp);os.chmod(tmp,0o600);os.replace(tmp,old)
        os.chmod(candidate,0o640);os.replace(candidate,COOKIE)
        print('Cookies получены и проверены непосредственно на VPS. Каналы не перезапущены.')
    finally:
        Path(candidate).unlink(missing_ok=True);Path(docfile).unlink(missing_ok=True)

def put(path, data, uid=0, gid=None, mode=0o640):
    if gid is None: gid=grp.getgrnam('openflux').gr_gid
    fd,tmp=tempfile.mkstemp(prefix='.volga-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data)
        os.chown(tmp,uid,gid);os.chmod(tmp,mode);os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def configure(channel, source):
    if not re.fullmatch('[1-8]',channel):raise ValueError('Канал должен быть от 1 до 8')
    root=Path('/etc/openflux'); mode=(root/'pool.mode').read_text().strip()
    if mode not in ('classic','multistream'):raise ValueError('Неизвестный режим пула')
    urls=validate(Path(source).read_text(),mode)
    preflight(source)  # Authentication must succeed before any configuration write.
    primary=root/'instances'/f'{channel}.env'
    if not primary.is_file():raise ValueError('Сначала инициализируйте канал через меню OpenFlux')
    data=primary.read_text()
    for key,value in {'URL':urls,'TRANSPORT':'vyandex','ROLE':'exit','MODE':'l4','POOL_MODE':mode}.items():
        line=key+'="'+value+'"'
        if re.search('^'+key+'=',data,re.M): data=re.sub('^'+key+'=.*$',lambda _:line,data,flags=re.M)
        else:data=data.rstrip()+'\n'+line+'\n'
    # CODEC and ENCRYPTION_KEY remain exactly as configured for this channel.
    targets=[primary,root/'profiles'/mode/f'{channel}.env']
    if channel=='1':targets.append(root/'openflux.env')
    backup=Path(tempfile.mkdtemp(prefix='x-manager-volga-channel-',dir='/var/backups'))
    saved={}
    for i,path in enumerate(targets):
        if not path.parent.is_dir():raise ValueError('Профиль канала не инициализирован')
        if path.exists():
            shutil.copy2(path,backup/str(i));st=path.stat()
            saved[path]=(path.read_bytes(),st.st_uid,st.st_gid,st.st_mode&0o777)
        else:saved[path]=None
    (backup/'paths.json').write_text(json.dumps([str(p) for p in targets]))
    unit='openflux@'+channel
    active=subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0
    enabled=subprocess.run(['systemctl','is-enabled','--quiet',unit]).returncode==0
    try:
        for path in targets:put(path,data.encode())
        subprocess.run(['systemctl','restart',unit],check=True)
        time.sleep(5)
        subprocess.run(['systemctl','is-active','--quiet',unit],check=True)
        pid=subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value'])
        time.sleep(3)
        if pid.strip()==b'0' or pid!=subprocess.check_output(['systemctl','show',unit,'-p','MainPID','--value']):
            raise ValueError('Канал перезапускается вместо устойчивого запуска')
        subprocess.run(['systemctl','enable',unit],check=True)
    except BaseException:
        subprocess.run(['systemctl','stop',unit],check=True)
        for path,value in saved.items():
            if value is None:path.unlink(missing_ok=True)
            else:put(path,*value)
        if not enabled:subprocess.run(['systemctl','disable',unit],check=True)
        if active:subprocess.run(['systemctl','start',unit],check=True)
        print('Предыдущая конфигурация восстановлена. Резервная копия:',backup)
        raise
    print('Волга: авторизация проверена, канал запущен. Резервная копия:',backup)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['validate','check','cookies','configure','refresh','instructions']);parser.add_argument('path',nargs='?');parser.add_argument('--channel')
    a=parser.parse_args()
    if a.action=='instructions':
        parts=os.environ.get('SSH_CONNECTION','').split()
        host=parts[2] if len(parts)==4 else 'IP_СЕРВЕРА'
        port=parts[3] if len(parts)==4 else 'SSH_ПОРТ'
        print(f'''Обновление на VPS работает без компьютера, пока Яндекс не требует ручную SmartCaptcha.
Для ручной капчи нужен браузер с выходом через IP этого VPS.

1. На вашем компьютере откройте терминал и оставьте команду работающей:
   ssh -N -D 127.0.0.1:18791 -p {port} -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 root@{host}
   Если порт 18791 занят, выберите свободный и используйте его во всех следующих шагах.
   В первый раз сверьте SSH-отпечаток сервера. Не отключайте проверку ключа.

2. В другом окне PowerShell скачайте помощник с этого же сервера:
   scp -P {port} root@{host}:/usr/local/share/x-manager/scripts/volga-cookie-capture.ps1 .
   powershell -NoProfile -ExecutionPolicy Bypass -File .\\volga-cookie-capture.ps1 -ServerHost {host} -SshPort {port} -SocksPort 18791

3. Вставьте ссылку документа. Откроется отдельный Chrome через SOCKS5-туннель.
   Пройдите капчу и дождитесь редактора. Затем нажмите Enter в окне помощника.
   Он заберёт только cookies Яндекса (включая HttpOnly) и передаст их на VPS по SSH.
   Пароль SSH вводится в терминале; в скрипте он не хранится.

4. В меню «Cookies Волги» выберите «Получить и проверить cookies сейчас».
   После успеха закройте отдельный Chrome и остановите SSH-туннель Ctrl+C.
   Для конфиденциальности удалите отдельный временный профиль, путь к которому покажет помощник.

Если компьютера нет: в SSH-приложении на телефоне нужен динамический SOCKS5-туннель
и браузер с поддержкой этого прокси и экспорта Netscape cookies с HttpOnly.
Универсальной команды для всех мобильных приложений нет. Полученный файл можно
передать на VPS по SFTP и выбрать «Импортировать cookies из файла на VPS».
Не присылайте cookies в чат. Ручную капчу скрипт не решает.''')
    elif a.action=='refresh':refresh()
    elif not a.path:parser.error('Для выбранного действия нужен путь к файлу')
    elif a.action=='validate':validate(Path(a.path).read_text())
    elif a.action=='check':preflight(a.path)
    elif a.action=='cookies':cookies(a.path)
    else:configure(a.channel or '',a.path)

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        # CalledProcessError.cmd may contain private filenames; no source contents.
        print('Ошибка Волги:',str(exc) if isinstance(exc,ValueError) else type(exc).__name__,file=__import__('sys').stderr)
        raise SystemExit(1)
