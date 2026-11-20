$ErrorActionPreference = 'Stop'
# 把 dist 里的程序与规则复制到指定目录，并（可选）创建桌面快捷方式。
# 这是“免安装/便携”部署脚本；需要写入“应用和功能”请用 build-installer.ps1 生成的安装包。
param(
    [string]$TargetDir = (Join-Path $env:LOCALAPPDATA ('Programs\' + [string][char]0x6EE1 + [char]0x552F + [char]0x6740 + [char]0x6BD2)),
    [switch]$NoShortcut
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$appName = [string][char]0x6EE1 + [char]0x552F + [char]0x6740 + [char]0x6BD2
$src = Join-Path $root 'dist'
$exe = Join-Path $TargetDir ($appName + '.exe')

Get-Process | Where-Object { $_.Path -like ('*' + $appName + '*') } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

if (-not (Test-Path $src)) { throw "找不到 $src，请先运行 build.ps1" }
New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
Copy-Item (Join-Path $src ($appName + '.exe')) $exe -Force
foreach ($sub in @('rules', 'tests')) {
    $d = Join-Path $TargetDir $sub
    if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    Copy-Item (Join-Path $src $sub) $d -Recurse -Force
}

$lnkPath = ''
if (-not $NoShortcut) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $lnkPath = Join-Path $desktop ($appName + '.lnk')
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = $exe
    $lnk.WorkingDirectory = $TargetDir
    $lnk.IconLocation = $exe + ',0'
    $lnk.Description = $appName
    $lnk.Save()
}

Write-Output ('EXE|' + $exe + '|' + (Test-Path $exe))
if ($lnkPath -ne '') { Write-Output ('LNK|' + $lnkPath + '|' + (Test-Path $lnkPath)) }
Write-Output 'DONE'
