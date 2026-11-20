$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe not found: $csc" }

$dist = Join-Path $root 'dist'
$appName = [string][char]0x6EE1 + [char]0x552F + [char]0x6740 + [char]0x6BD2
$setupName = $appName + [string][char]0x2D + [string][char]0x5B89 + [char]0x88C5 + [char]0x7A0B + [char]0x5E8F
$appExe = Join-Path $dist ($appName + '.exe')
$rules = Join-Path $dist 'rules\signatures.json'
$readme = Join-Path $root 'README.md'
$out = Join-Path $dist ($setupName + '.exe')
$rulesGz = Join-Path (Join-Path $dist 'rules') 'signatures.json.gz'

if (-not (Test-Path $appExe)) { throw "先运行 build.ps1 生成 $appName.exe" }
if (-not (Test-Path $rules)) { throw "缺少 $rules" }

$setupSrc = Join-Path $root 'installer\Setup.cs'
$setupManifest = Join-Path $root 'installer\app.manifest'
$setupInfo = Join-Path $root 'installer\AssemblyInfo.cs'
$icon = Join-Path $root 'assets\app.ico'

$argsList = @(
  '/nologo',
  '/target:winexe',
  '/platform:anycpu',
  '/optimize+',
  '/codepage:65001',
  ('/win32icon:' + $icon),
  ('/win32manifest:' + $setupManifest),
  ('/out:' + $out),
  '/r:System.dll',
  '/r:System.Core.dll',
  '/r:System.Windows.Forms.dll',
  '/r:System.Drawing.dll',
  ('/resource:' + $appExe + ',app.exe'),
  ('/resource:' + $rulesGz + ',rules.json.gz'),
  ('/resource:' + $readme + ',readme.txt'),
  $setupSrc,
  $setupInfo
)

$inBytes = [System.IO.File]::ReadAllBytes($rules)
$outFs = [System.IO.File]::Create($rulesGz)
$gz = New-Object System.IO.Compression.GZipStream($outFs, [System.IO.Compression.CompressionMode]::Compress)
$gz.Write($inBytes, 0, $inBytes.Length)
$gz.Close()
$outFs.Close()

& $csc $argsList
if (Test-Path $rulesGz) { Remove-Item $rulesGz -Force }
if ($LASTEXITCODE -ne 0) { throw ("compile failed, exit " + $LASTEXITCODE) }

$size = (Get-Item $out).Length
Write-Host ("OK -> " + $out + " (" + [math]::Round($size / 1KB, 1) + " KB)")
