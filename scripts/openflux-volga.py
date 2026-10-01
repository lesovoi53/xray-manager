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
ROOT = Path('/etc/openflux')

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
    check_document(cmd,260)

def check_document(cmd, timeout):
    try:
        subprocess.run(cmd,check=True,timeout=timeout,capture_output=True,text=True)
    except subprocess.CalledProcessError as exc:
        detail=(exc.stderr or '')+'\n'+(exc.stdout or '')
        if 'SmartCaptcha' in detail:
            raise ValueError('Яндекс требует ручную SmartCaptcha с IP VPS. Откройте «Cookies Волги» → [6] Инструкция; после передачи cookies повторите проверку.') from None
        if 'OnlyOffice' in detail:
            raise ValueError('Документ открыт в OnlyOffice. Нужен новый редактор Яндекс Волга и доступ на редактирование.') from None
        # Preserve the actual error privately instead of losing it in a generic
        # CalledProcessError or copying potentially private URLs to the journal.
        report=ROOT/'volga-check-error.txt'
        put(report,detail.encode(),uid=os.geteuid(),gid=os.getegid(),mode=0o600)
        raise ValueError(f'Проверка документа Волги завершилась с кодом {exc.returncode}. Подробности в закрытом файле {report}; рабочая конфигурация не изменена.') from None
    except subprocess.TimeoutExpired:
        raise ValueError('Истекло время проверки документа Волги. Проверьте доступность Яндекса; рабочая конфигурация не изменена.') from None

def draft_path(channel):
    if not re.fullmatch('[1-8]',channel):raise ValueError('Канал должен быть от 1 до 8')
    mode=(ROOT/'pool.mode').read_text().strip()
    if mode not in ('classic','multistream'):raise ValueError('Неизвестный режим пула')
    return ROOT/'volga-drafts'/mode/f'{channel}.urls',mode

def save_draft(channel, urls):
    path,mode=draft_path(channel)
    urls=validate(urls,mode)
    gid=grp.getgrnam('openflux').gr_gid
    for directory in [path.parent.parent,path.parent]:
        if directory.is_symlink():raise ValueError('Недопустимый путь черновика Волги')
        directory.mkdir(mode=0o750,exist_ok=True)
        os.chown(directory,0,gid);os.chmod(directory,0o750)
    if path.is_symlink():raise ValueError('Недопустимый файл черновика Волги')
    put(path,urls.encode(),gid=gid)
    return path

def draft_info():
    channels=documents=0
    for file in sorted((ROOT/'instances').glob('[1-8].env')):
        props={k:v.strip().strip('"').strip("'") for k,v in (l.split('=',1) for l in file.read_text().splitlines() if '=' in l and not l.lstrip().startswith('#'))}
        if props.get('TRANSPORT')=='vyandex' and props.get('URL'):
            channels+=1
            documents+=len(validate(props['URL']).split(','))
    print(f'Сохранённые каналы Волги: {channels}; документов: {documents}.')
    print('Файл cookies: '+('есть; проверить авторизацию — пункт [1].' if COOKIE.is_file() else 'нет; получить через браузер — пункт [6].'))
    found=False
    for channel in map(str,range(1,9)):
        path,mode=draft_path(channel)
        if path.is_file():
            urls=validate(path.read_text(),mode)
            print(f'Канал {channel}: черновик {mode}, документов: {len(urls.split(","))}.')
            found=True
    if not found:
        print('Незавершённых настроек нет. Пункт [7] не нужен для уже сохранённых каналов.' if channels else 'Нет каналов и черновиков Волги. Сначала добавьте ссылки в разделе «Каналы».')

def resume(channel):
    path,_=draft_path(channel)
    if not path.is_file():raise ValueError('У этого канала нет черновика в текущем режиме. Сначала введите ссылки в разделе «Каналы».')
    configure(channel,path)

def discard(channel):
    path,_=draft_path(channel)
    path.unlink(missing_ok=True)
    print('Черновик удалён. Рабочий канал не изменён.')

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
    for file in sorted((ROOT/'instances').glob('[1-8].env')):
        props={k:v.strip().strip('"').strip("'") for k,v in (l.split('=',1) for l in file.read_text().splitlines() if '=' in l)}
        if props.get('TRANSPORT')=='vyandex' and props.get('URL'):
            docs.extend(validate(props['URL']).split(','))
    using_drafts=not docs
    if using_drafts:
        for channel in map(str,range(1,9)):
            path,mode=draft_path(channel)
            if path.is_file():docs.extend(validate(path.read_text(),mode).split(','))
    docs=list(dict.fromkeys(docs))
    if not docs:raise ValueError('Нет каналов или черновиков Волги. Сначала введите ссылки в разделе «Каналы»; при отказе авторизации они сохранятся как черновик.')
    if using_drafts:print('Проверка cookies по черновикам; рабочие каналы не изменяются.',flush=True)
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
            check_document([CHECK,'--url-file='+docfile,'--cookies-file='+candidate],70)
        if COOKIE.exists():
            old=COOKIE.with_name('yandex-cookies.previous.txt')
            fd,tmp=tempfile.mkstemp(prefix='.cookies-backup-',dir=COOKIE.parent);os.close(fd)
            shutil.copyfile(COOKIE,tmp);os.chmod(tmp,0o600);os.replace(tmp,old)
        os.chmod(candidate,0o640);os.replace(candidate,COOKIE)
        print('Cookies получены и проверены непосредственно на VPS. Каналы не перезапущены.')
        if using_drafts:print('Теперь выберите «Cookies Волги» → [7] Продолжить настройку из черновика.')
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
    root=ROOT; mode=(root/'pool.mode').read_text().strip()
    if mode not in ('classic','multistream'):raise ValueError('Неизвестный режим пула')
    urls=validate(Path(source).read_text(),mode)
    primary=root/'instances'/f'{channel}.env'
    if not primary.is_file():raise ValueError('Сначала инициализируйте канал через меню OpenFlux')
    draft=save_draft(channel,urls)
    try:
        preflight(draft)  # No live configuration writes before authentication.
    except (ValueError,OSError,subprocess.SubprocessError):
        print(f'Ссылки канала {channel} сохранены как черновик ({mode}). Рабочий канал не изменён. После получения cookies: «Cookies Волги» → [7] Продолжить настройку из черновика.',flush=True)
        raise
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
    draft.unlink(missing_ok=True)

def windows_command(host, port):
    if not re.fullmatch(r'[A-Za-z0-9._:-]+',host) or not (str(port).isdigit() or port=='SSH_PORT'):
        raise ValueError('Некорректный адрес SSH для команды Windows')
    return ("& { $ErrorActionPreference='Stop'; $d=Join-Path $env:USERPROFILE 'VolgaCookies'; "
            "New-Item -ItemType Directory -Force -Path $d | Out-Null; "
            "$f=Join-Path $d 'volga-cookie-capture.ps1'; "
            f"scp.exe -P {port} 'root@{host}:/usr/local/share/x-manager/scripts/volga-cookie-capture.ps1' $f; "
            "if ($LASTEXITCODE -ne 0) { throw 'Helper download failed' }; "
            f"& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f -ServerHost '{host}' -SshPort {port} -SocksPort 18791 }}")

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['validate','check','cookies','configure','refresh','instructions','drafts','resume','discard']);parser.add_argument('path',nargs='?');parser.add_argument('--channel')
    a=parser.parse_args()
    if a.action=='instructions':
        parts=os.environ.get('SSH_CONNECTION','').split()
        host=parts[2] if len(parts)==4 else 'SERVER_IP'
        port=parts[3] if len(parts)==4 else 'SSH_PORT'
        print(f'''Обновление на VPS работает без компьютера, пока Яндекс не требует ручную SmartCaptcha.
Для ручной капчи нужен браузер с выходом через IP этого VPS.

1. Скопируйте ОДНУ строку целиком в обычный Windows PowerShell:

{windows_command(host,port)}

   Команда сама скачает актуальный помощник в вашу пользовательскую папку.
   Работает и при запуске из C:\\Windows; права администратора не нужны.
   Если вместо адреса/порта показаны SERVER_IP / SSH_PORT, замените их своими.

2. Вставьте одну ссылку документа. Помощник сам откроет отдельное окно SSH:
   введите пароль сервера в этом окне и оставьте его открытым.
   В первый раз сверьте SSH-отпечаток. Не отключайте проверку ключа.
   Если порт 18791 занят, помощник выберет свободный.
   После проверки SOCKS5 и HTTPS через VPS откроется отдельный Chrome.

3. В отдельном Chrome откройте документ.
   Пройдите капчу и дождитесь редактора. Затем нажмите Enter в окне помощника.
   Он заберёт только cookies Яндекса (включая HttpOnly) и передаст их на VPS по SSH.
   Пароль может потребоваться повторно для передачи и проверки; в скрипте он не хранится.

4. Помощник запустит проверку cookies на VPS и покажет результат.
   Для первой настройки сначала введите ссылки в разделе «Каналы»:
   даже при отказе авторизации они останутся в черновике.
   Только если есть незавершённый черновик, выберите [7] для его применения.
   Для уже сохранённых каналов повторная настройка через [7] не нужна.
   Туннель помощника закроется автоматически; закройте отдельный Chrome.
   Для конфиденциальности удалите отдельный временный профиль, путь к которому покажет помощник.

Если компьютера нет: в SSH-приложении на телефоне нужен динамический SOCKS5-туннель
и браузер с поддержкой этого прокси и экспорта Netscape cookies с HttpOnly.
Универсальной команды для всех мобильных приложений нет. Полученный файл можно
передать на VPS по SFTP и выбрать «Импортировать cookies из файла на VPS».
Не присылайте cookies в чат. Ручную капчу скрипт не решает.''')
    elif a.action=='refresh':refresh()
    elif a.action=='drafts':draft_info()
    elif a.action=='resume':resume(a.channel or '')
    elif a.action=='discard':discard(a.channel or '')
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
