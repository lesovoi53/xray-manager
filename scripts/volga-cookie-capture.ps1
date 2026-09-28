param([Parameter(Mandatory=$true)][string]$ServerHost, [int]$SshPort=22, [int]$SocksPort=18791)
$ErrorActionPreference='Stop'
if ($ServerHost -notmatch '^[a-zA-Z0-9.-]+$' -or $SshPort -lt 1 -or $SshPort -gt 65535) { throw 'Invalid server address or SSH port' }
$doc=Read-Host 'Paste the Yandex document URL'
$parsed=[Uri]$doc
if ($parsed.Scheme -ne 'https' -or $parsed.Host -notin @('disk.yandex.ru','docs.yandex.ru')) { throw 'Expected a Yandex document HTTPS URL' }
$chrome=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $chrome) { throw 'Google Chrome is required for this optional CAPTCHA helper' }
$socket=[Net.Sockets.TcpClient]::new()
try { $socket.Connect('127.0.0.1',$SocksPort) } finally { $socket.Dispose() }
$profile=Join-Path $env:TEMP ('volga-browser-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($profile) | Out-Null
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$listener.Start();$debugPort=$listener.LocalEndpoint.Port;$listener.Stop()
Start-Process -FilePath $chrome -ArgumentList @("--user-data-dir=`"$profile`"", "--proxy-server=socks5://127.0.0.1:$SocksPort", "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=$debugPort", '--no-first-run', '--no-default-browser-check', '--host-resolver-rules="MAP * ~NOTFOUND, EXCLUDE localhost"', "`"$doc`"")
Read-Host 'Complete CAPTCHA in the separate window and wait for the document to open. Then press Enter' | Out-Null
$meta=Invoke-RestMethod -Uri "http://127.0.0.1:$debugPort/json/version" -TimeoutSec 10
$endpoint=[Uri]$meta.webSocketDebuggerUrl
if ($endpoint.Host -notin @('localhost','127.0.0.1') -or $endpoint.Port -ne $debugPort) { throw 'Unexpected browser endpoint' }
$ws=[Net.WebSockets.ClientWebSocket]::new();$timeout=[Threading.CancellationTokenSource]::new(15000)
$localFile=Join-Path $profile 'yandex-cookies.txt'
$remoteFile='/root/volga-cookies-'+[Guid]::NewGuid().ToString('N')+'.txt'
try {
 $ws.ConnectAsync($endpoint,$timeout.Token).GetAwaiter().GetResult()
 $bytes=[Text.Encoding]::UTF8.GetBytes('{"id":1,"method":"Storage.getCookies"}')
 $ws.SendAsync([ArraySegment[byte]]::new($bytes),[Net.WebSockets.WebSocketMessageType]::Text,$true,$timeout.Token).GetAwaiter().GetResult()
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
 Write-Host 'Only Yandex cookies transferred. Use Volga cookies menu item 1 to verify all documents.'
} finally {
 if (Test-Path -LiteralPath $localFile) { Remove-Item -LiteralPath $localFile }
 $ws.Dispose();$timeout.Dispose()
 Write-Host "Close the separate Chrome window after finishing. Its isolated profile is: $profile"
}
