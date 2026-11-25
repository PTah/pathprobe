#Requires -Version 5.1
<#
.SYNOPSIS
  Сборка pathprobe-gui.exe (PyInstaller, Windows amd64).

.EXAMPLE
  .\scripts\build-windows-exe.ps1
#>
param(
    [string]$Python = "",
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"
$utf8 = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$null = cmd /c "chcp 65001 >NUL"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not $Python) {
    $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
    if (Test-Path $venvPy) { $Python = $venvPy } else { $Python = "python" }
}

Write-Host "[*] Python: $Python" -ForegroundColor Cyan
& $Python -m pip install -q -e ".[gui]" "pyinstaller>=6.0"

$version = & $Python -c "from pathprobe import __version__; print(__version__)"
$version = "$version".Trim()
Write-Host "[*] Version: $version" -ForegroundColor Cyan

if (Test-Path (Join-Path $Root "build\pyinstaller")) {
    Remove-Item (Join-Path $Root "build\pyinstaller") -Recurse -Force
}
$distGui = Join-Path $Root "dist\gui"
if (Test-Path $distGui) { Remove-Item $distGui -Recurse -Force }
New-Item -ItemType Directory -Path $distGui | Out-Null

& $Python -m PyInstaller `
    --noconfirm `
    --clean `
    --distpath $distGui `
    --workpath (Join-Path $Root "build\pyinstaller") `
    (Join-Path $Root "pathprobe-gui.spec")

$exe = Join-Path $distGui "pathprobe-gui.exe"
if (-not (Test-Path $exe)) { throw "exe not found: $exe" }

Copy-Item (Join-Path $Root "config.example.yaml") (Join-Path $distGui "config.example.yaml") -Force
$cfgOut = Join-Path $distGui "config.yaml"
if (-not (Test-Path $cfgOut)) {
    Copy-Item (Join-Path $Root "config.example.yaml") $cfgOut -Force
} else {
    Write-Host "[*] keep existing config.yaml in dist/gui" -ForegroundColor Yellow
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLowerInvariant()
$hashFile = Join-Path $distGui "pathprobe-gui.exe.sha256"
# хеш исполняемого файла (как в release-discipline)
Set-Content -Path $hashFile -Value "$hash  pathprobe-gui.exe" -Encoding ascii

if (-not $SkipZip) {
    $zipName = "pathprobe-$version-windows-amd64.zip"
    $zipPath = Join-Path $Root "dist\$zipName"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $distGui "*") -DestinationPath $zipPath -Force
    Write-Host "[+] ZIP: $zipPath" -ForegroundColor Green
}

Write-Host "[+] EXE: $exe" -ForegroundColor Green
Write-Host "[+] SHA256: $hash" -ForegroundColor Green
Write-Host "Рядом с exe положите свой config.yaml (сейчас скопирован пример)." -ForegroundColor Yellow
