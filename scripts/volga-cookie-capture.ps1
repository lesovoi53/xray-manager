param([Parameter(Mandatory=$true)][string]$ServerHost, [int]$SshPort=22, [int]$SocksPort=18791, [string]$DocumentUrl='')
$ErrorActionPreference='Stop'

function Get-FreeLoopbackPort([int]$Preferred=0) {
 $listener=$null
 try {
  $listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$Preferred)
  $listener.Server.ExclusiveAddressUse=$true
  $listener.Start()
  return [int]$listener.LocalEndpoint.Port
 } catch {
  if ($Preferred -eq 0) { throw }
  return Get-FreeLoopbackPort 0
 } finally { if ($listener) { $listener.Stop() } }
}

function Test-Socks5([int]$Port) {
 $client=[Net.Sockets.TcpClient]::new()
 try {
  $task=$client.ConnectAsync('127.0.0.1',$Port)
  if (-not $task.Wait(800)) { return $false }
  $stream=$client.GetStream();$stream.ReadTimeout=800;$stream.WriteTimeout=800
  $greeting=[byte[]]@(5,1,0);$stream.Write($greeting,0,3)
  return ($stream.ReadByte() -eq 5 -and $stream.ReadByte() -eq 0)
 } catch { return $false } finally { $client.Dispose() }
}

function Start-VolgaTunnel([string]$Target,[int]$Port,[int]$LocalPort) {
 # Always own a new tunnel; never trust an arbitrary pre-existing listener.
 $selected=Get-FreeLoopbackPort $LocalPort
 $ssh=(Get-Command ssh.exe -ErrorAction Stop).Source
 Write-Host "An SSH window will open. Enter the server password there and keep it open. SOCKS port: $selected"
 $sshArguments=@('-N','-T','-D',"127.0.0.1:$selected",'-p',"$Port",'-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=30','-o','ServerAliveCountMax=3','-o','ConnectTimeout=15','-o','StrictHostKeyChecking=ask',"root@$Target")
 $proc=Start-Process -FilePath $ssh -ArgumentList $sshArguments -PassThru -WindowStyle Normal
 try {
  $deadline=[DateTime]::UtcNow.AddMinutes(3)
  while ([DateTime]::UtcNow -lt $deadline) {
   if ($proc.HasExited) { throw "SSH tunnel closed (exit $($proc.ExitCode)). Check the SSH window for the connection/authentication error." }
   if (Test-Socks5 $selected) { return [pscustomobject]@{Process=$proc;Port=$selected} }
   Start-Sleep -Milliseconds 300
  }
  throw 'SSH authentication timed out. Run the helper again and enter the password in the SSH window.'
 } catch {
  if (-not $proc.HasExited) { $proc.Kill();$proc.WaitForExit() }
  throw
 }
}

# Dot-sourcing exposes only the functions for isolated regression tests.
if ($MyInvocation.InvocationName -eq '.') { return }
if ($ServerHost -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*$' -or $SshPort -lt 1 -or $SshPort -gt 65535 -or $SocksPort -lt 1 -or $SocksPort -gt 65535) { throw 'Invalid server address or SSH/SOCKS port' }
foreach ($command in @('ssh.exe','scp.exe','curl.exe')) { Get-Command $command -ErrorAction Stop | Out-Null }
$doc=$DocumentUrl
if (-not $doc) { $doc=Read-Host 'Paste one Yandex document URL' }
$parsed=[Uri]$doc
if ($parsed.Scheme -ne 'https' -or $parsed.Host -notin @('disk.yandex.ru','docs.yandex.ru') -or $parsed.UserInfo -or $parsed.Port -ne 443 -or $doc -match '[\s"<>]') { throw 'Expected a single Yandex document HTTPS URL' }
$chrome=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $chrome) { throw 'Google Chrome was not found. Install Chrome and run this helper again.' }
$browserProfile=Join-Path $env:LOCALAPPDATA ('XManager\Volga\'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($browserProfile) | Out-Null
$localFile=Join-Path $browserProfile 'yandex-cookies.txt'
$remoteFile='/root/volga-cookies-'+[Guid]::NewGuid().ToString('N')+'.txt'
$tunnel=$null;$ws=$null;$timeout=$null
try {
 $tunnel=Start-VolgaTunnel $ServerHost $SshPort $SocksPort
 $SocksPort=$tunnel.Port
 $probe=& curl.exe --silent --show-error --proxy "socks5h://127.0.0.1:$SocksPort" --noproxy localhost --connect-timeout 10 --max-time 20 --output NUL --write-out '%{http_code}' 'https://disk.yandex.ru/'
 if ($LASTEXITCODE -ne 0 -or $probe -notmatch '^[1-5][0-9][0-9]$') { throw 'SSH connected, but HTTPS through this VPS failed. Chrome was not opened; see the curl error above.' }
 $debugPort=Get-FreeLoopbackPort
 Start-Process -FilePath $chrome -WindowStyle Normal -ArgumentList @("--user-data-dir=`"$browserProfile`"", "--proxy-server=socks5://127.0.0.1:$SocksPort", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=$debugPort", '--no-first-run', '--no-default-browser-check', '--new-window', "`"$doc`"")
 $meta=$null
 for ($attempt=0;$attempt -lt 40;$attempt++) {
  if ($tunnel.Process.HasExited) { throw 'SSH tunnel closed. Run the helper again and keep the SSH window open.' }
  try { $meta=Invoke-RestMethod -Uri "http://127.0.0.1:$debugPort/json/version" -TimeoutSec 1; break } catch { Start-Sleep -Milliseconds 250 }
 }
 if (-not $meta) { throw "Chrome did not start its separate session. Close only the Volga window and retry. Profile: $browserProfile" }
 Write-Host 'Chrome and the SSH tunnel are ready. Complete CAPTCHA and wait for the document editor.'
 $verified=$false
 while (-not $verified) {
 try {
 Read-Host 'Only after the document opens, press Enter here to transfer Yandex cookies' | Out-Null
 if (-not (Test-Socks5 $SocksPort)) { throw 'The SSH tunnel is not available. Keep its SSH window open; no cookies have been transferred.' }
 $tabs=Invoke-RestMethod -Uri "http://127.0.0.1:$debugPort/json/list" -TimeoutSec 5
 $editor=@($tabs | Where-Object { $_.type -eq 'page' -and $_.url -match '^https://docs\.yandex\.ru/(edit|docs)/' })
 if ($editor.Count -eq 0) {
  Write-Host 'The document editor is not open yet. Complete CAPTCHA/load the document first. The tunnel stays open.'
  continue
 }
 $endpoint=[Uri]$meta.webSocketDebuggerUrl
 if ($endpoint.Host -notin @('localhost','127.0.0.1') -or $endpoint.Port -ne $debugPort) { throw 'Unexpected browser endpoint' }
 $ws=[Net.WebSockets.ClientWebSocket]::new();$timeout=[Threading.CancellationTokenSource]::new(15000)
 $ws.ConnectAsync($endpoint,$timeout.Token).GetAwaiter().GetResult() | Out-Null
 $bytes=[Text.Encoding]::UTF8.GetBytes('{"id":1,"method":"Storage.getCookies"}')
 $ws.SendAsync([ArraySegment[byte]]::new($bytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,$timeout.Token).GetAwaiter().GetResult() | Out-Null
 do {
  $stream=[IO.MemoryStream]::new();$buffer=New-Object byte[] 65536
  do {
   $received=$ws.ReceiveAsync([ArraySegment[byte]]::new($buffer),$timeout.Token).GetAwaiter().GetResult()
   if ($received.MessageType -eq [Net.WebSockets.WebSocketMessageType]::Close) { throw 'Browser closed' }
   $stream.Write($buffer,0,$received.Count)
   if ($stream.Length -gt 4194304) { throw 'Browser response too large' }
  } until ($received.EndOfMessage)
  $reply=[Text.Encoding]::UTF8.GetString($stream.ToArray()) | ConvertFrom-Json
  $stream.Dispose()
 } until ($reply.id -eq 1)
 if ($reply.error) { throw 'Browser did not return cookies' }
 $lines=[Collections.Generic.List[string]]::new();$lines.Add('# Netscape HTTP Cookie File')
 foreach ($c in $reply.result.cookies) {
  $domain=$c.domain.TrimStart('.')
  if ($domain -ne 'yandex.ru' -and -not $domain.EndsWith('.yandex.ru')) { continue }
  $name=$c.domain
  if ($c.httpOnly) { $name='#HttpOnly_'+$name }
  $subdomain=if ($c.domain.StartsWith('.')) {'TRUE'} else {'FALSE'}
  $secure=if ($c.secure) {'TRUE'} else {'FALSE'}
  $expiry=[Math]::Max(0,[long]$c.expires)
  $fields=@($name,$subdomain,$c.path,$secure,[string]$expiry,$c.name,$c.value)
  if ($fields | Where-Object { $_ -match "[\r\n\t]" }) { throw 'Invalid cookie encoding' }
  $lines.Add(($fields -join "`t"))
 }
 if ($lines.Count -lt 2) { throw 'No Yandex cookies found' }
 [IO.File]::WriteAllText($localFile,($lines -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
 & scp -P $SshPort $localFile "root@${ServerHost}:$remoteFile"
 if ($LASTEXITCODE -ne 0) { throw 'Cookie upload failed' }
 & ssh -p $SshPort "root@$ServerHost" "python3 /usr/local/share/x-manager/scripts/openflux-volga.py cookies $remoteFile; result=`$?; rm -f -- $remoteFile; exit `$result"
 if ($LASTEXITCODE -ne 0) { throw 'Server rejected cookies; existing cookies preserved' }
 & ssh -p $SshPort "root@$ServerHost" 'systemctl start volga-cookies.service; result=$?; if [ "$result" -ne 0 ]; then journalctl -u volga-cookies.service -n 8 --no-pager; fi; exit "$result"'
 if ($LASTEXITCODE -ne 0) { throw 'Cookies imported, but document verification failed. See the server error above; the channel was not changed.' }
 Write-Host 'Yandex cookies transferred and verified. Existing configured channels do not need draft setup. Only for an unfinished draft: X-Manager -> Volga cookies -> 7 -> channel number.'
 $verified=$true
 } catch {
  Write-Warning $_.Exception.Message
  $retry=Read-Host 'The browser/tunnel are kept open. Type R to retry after correcting the problem, or Q to close the helper'
  if ($retry -notmatch '^[Rr]$') { throw }
 } finally {
  if (Test-Path -LiteralPath $localFile) { Remove-Item -LiteralPath $localFile }
  if ($ws) {$ws.Dispose();$ws=$null};if ($timeout) {$timeout.Dispose();$timeout=$null}
 }
 }
} finally {
 if (Test-Path -LiteralPath $localFile) { Remove-Item -LiteralPath $localFile }
 if ($ws) { $ws.Dispose() };if ($timeout) { $timeout.Dispose() }
 if ($tunnel -and -not $tunnel.Process.HasExited) { $tunnel.Process.Kill();$tunnel.Process.WaitForExit() }
 Write-Host "The helper's SSH tunnel is closed. Close the separate Chrome window. Private browser profile: $browserProfile"
}
