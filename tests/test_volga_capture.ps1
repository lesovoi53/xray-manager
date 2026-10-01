param([string]$LauncherFile='')
$ErrorActionPreference='Stop'
$helper=Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts/volga-cookie-capture.ps1'
$parseErrors=$null;$parseTokens=$null
[System.Management.Automation.Language.Parser]::ParseFile($helper,[ref]$parseTokens,[ref]$parseErrors) | Out-Null
if ($parseErrors) { throw 'Helper syntax errors' }
. $helper -ServerHost fixture.invalid
Add-Type @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
public class VolgaSocksFixture : IDisposable {
 private TcpListener listener; private Thread worker;
 public int Port;
 public VolgaSocksFixture(byte version) {
  listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;
  worker=new Thread(()=>{try {using(var c=listener.AcceptTcpClient()) {var s=c.GetStream();s.ReadTimeout=2000;for(int i=0;i<3;i++)s.ReadByte();s.Write(new byte[]{version,0},0,2);}} catch(SocketException){} });
  worker.IsBackground=true;worker.Start();
 }
 public void Dispose() {listener.Stop();worker.Join(3000);}
}
'@
$valid=[VolgaSocksFixture]::new(5)
try { if (-not (Test-Socks5 $valid.Port)) { throw 'SOCKS5 greeting rejected' } } finally {$valid.Dispose()}
$invalid=[VolgaSocksFixture]::new(4)
try { if (Test-Socks5 $invalid.Port) { throw 'Non-SOCKS5 listener accepted' } } finally {$invalid.Dispose()}
$free=Get-FreeLoopbackPort
if (Test-Socks5 $free) {throw 'Closed port accepted'}
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$free);$listener.Start()
try {if ((Get-FreeLoopbackPort $free) -eq $free) {throw 'Occupied port reused'}} finally {$listener.Stop()}
Write-Host 'PASS: parser, actual SOCKS5 handshake, wrong protocol, closed port, occupied-port fallback.'
if ($LauncherFile) {
 $launcher=Get-Content -LiteralPath $LauncherFile -Raw
 $testRoot=Join-Path $env:TEMP ('volga-launcher-test-'+[Guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Path $testRoot | Out-Null
 $launcher=$launcher.Replace('$env:USERPROFILE',("'"+$testRoot.Replace("'","''")+"'"))
 $script:DownloadFails=$false;$script:HelperCalls=0
 function scp.exe {
  if ($script:DownloadFails) {$global:LASTEXITCODE=1;return}
  [IO.File]::WriteAllText($args[-1],'fixture');$global:LASTEXITCODE=0
 }
 function powershell.exe {
  $script:HelperCalls++
  $index=[Array]::IndexOf($args,'-File')
  if ($index -lt 0 -or -not (Test-Path -LiteralPath $args[$index+1])) {throw 'Downloaded helper not passed to child'}
  $global:LASTEXITCODE=0
 }
 try {
  & ([scriptblock]::Create($launcher))
  if ($script:HelperCalls -ne 1) {throw 'Launcher did not start helper'}
  $script:DownloadFails=$true;$failed=$false
  try {& ([scriptblock]::Create($launcher))} catch {$failed=$true}
  if (-not $failed -or $script:HelperCalls -ne 1) {throw 'Failed download launched stale helper'}
  Write-Host 'PASS: actual one-line launcher and failed-download refusal (mock SSH, no network).'
 } finally {
  $resolved=[IO.Path]::GetFullPath($testRoot)
  $tempPrefix=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
  if (-not $resolved.StartsWith($tempPrefix,[StringComparison]::OrdinalIgnoreCase)) {throw 'Unexpected test cleanup path'}
  Remove-Item -LiteralPath $resolved -Recurse -Force
 }
}
