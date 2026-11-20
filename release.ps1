$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $root 'dist'
$appName = [string][char]0x6EE1 + [char]0x552F + [char]0x6740 + [char]0x6BD2
$version = '1.0.0'

Write-Host '== 1/3 构建主程序与安装包 =='
& (Join-Path $root 'build.ps1')
if ($LASTEXITCODE -ne 0) { throw 'build.ps1 failed' }
& (Join-Path $root 'build-installer.ps1')
if ($LASTEXITCODE -ne 0) { throw 'build-installer.ps1 failed' }

$exe = Join-Path $dist ($appName + '.exe')
$setup = Join-Path $dist ($appName + '-安装程序.exe')
$rules = Join-Path $dist 'rules\signatures.json'
foreach ($f in @($exe, $setup, $rules)) {
    if (-not (Test-Path $f)) { throw "缺少 $f，请先运行 build.ps1 / build-installer.ps1" }
}

Write-Host '== 2/3 组装便携包 =='
$stage = Join-Path $dist ('release\' + $appName + '-' + $version)
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $stage 'rules') -Force | Out-Null
Copy-Item $exe $stage
Copy-Item $rules (Join-Path $stage 'rules') -Force
foreach ($doc in @('README.md', 'EULA.txt', 'PRIVACY.txt', 'CHANGELOG.md')) {
    $p = Join-Path $root $doc
    if (Test-Path $p) { Copy-Item $p $stage -Force }
}
$zip = Join-Path $dist ($appName + '-' + $version + '-portable.zip')
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal

Write-Host '== 3/3 生成校验值 =='
$lines = @()
foreach ($f in @($exe, $setup, $zip)) {
    $h = (Get-FileHash $f -Algorithm SHA256).Hash.ToLower()
    $lines += ($h + '  ' + (Split-Path $f -Leaf))
}
$sums = Join-Path $dist 'SHA256SUMS.txt'
[System.IO.File]::WriteAllLines($sums, $lines, (New-Object System.Text.UTF8Encoding($true)))

Write-Host ('主程序      : ' + $exe + ' (' + [math]::Round((Get-Item $exe).Length / 1KB, 1) + ' KB)')
Write-Host ('安装包      : ' + $setup + ' (' + [math]::Round((Get-Item $setup).Length / 1KB, 1) + ' KB)')
Write-Host ('便携包      : ' + $zip + ' (' + [math]::Round((Get-Item $zip).Length / 1KB, 1) + ' KB)')
Write-Host ('校验值      : ' + $sums)
Get-Content $sums | ForEach-Object { Write-Host ('  ' + $_) }
