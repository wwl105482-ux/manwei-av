$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$csc = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc.exe not found: $csc" }

$dist = Join-Path $root 'dist'
if (-not (Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }

$appName = [string][char]0x6EE1 + [char]0x552F + [char]0x6740 + [char]0x6BD2
$exePath = Join-Path $dist ($appName + '.exe')

# 先把规则与自检样本同步到 dist，再据此生成规则哈希，最后编译。
foreach ($name in @('rules', 'tests')) {
  $src = Join-Path $root $name
  $dst = Join-Path $dist $name
  if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
  Copy-Item $src $dst -Recurse -Force
}

$rulesFile = Join-Path $dist (Join-Path 'rules' 'signatures.json')
$rulesHash = (Get-FileHash $rulesFile -Algorithm SHA256).Hash.ToLowerInvariant()
$hashFile = Join-Path $root (Join-Path 'src' 'RulesHash.g.cs')
$hashBody = 'namespace GuardScan { internal static class RulesHash { public const string Sha256 = "' + $rulesHash + '"; } }'
Set-Content -Path $hashFile -Value $hashBody -Encoding UTF8

$sources = Get-ChildItem (Join-Path $root 'src') -Filter *.cs | ForEach-Object { $_.FullName }
$refs = @(
  'System.dll',
  'System.Core.dll',
  'System.Windows.Forms.dll',
  'System.Drawing.dll',
  'System.Web.Extensions.dll',
  'System.Xml.dll',
  'System.IO.Compression.dll',
  'System.IO.Compression.FileSystem.dll'
)

$argsList = @(
  '/nologo',
  '/target:winexe',
  '/platform:anycpu',
  '/optimize+',
  '/codepage:65001',
  ('/win32manifest:' + (Join-Path $root 'app.manifest')),
  ('/win32icon:' + (Join-Path $root 'assets\app.ico')),
  ('/out:' + $exePath)
)
foreach ($r in $refs) { $argsList += ('/r:' + $r) }
$argsList += $sources

& $csc $argsList
if ($LASTEXITCODE -ne 0) { throw ("compile failed, exit " + $LASTEXITCODE) }

$size = (Get-Item $exePath).Length
Write-Host ("OK -> " + $exePath + " (" + [math]::Round($size / 1KB, 1) + " KB)")
