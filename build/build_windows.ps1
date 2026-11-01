# Build surreal.exe on Windows:  powershell -ExecutionPolicy Bypass -File build\build_windows.ps1
#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root

Write-Host "== surreal: test ==" -ForegroundColor Cyan
python run_tests.py
if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }

Write-Host "== surreal: build surreal.exe ==" -ForegroundColor Cyan
python -m pip install --upgrade --quiet pyinstaller
if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }
python -m PyInstaller --clean --noconfirm build\surreal.spec
if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }

$exe = Join-Path $root "dist\surreal.exe"
if (-not (Test-Path $exe)) { Write-Error "build produced no dist\surreal.exe"; Pop-Location; exit 1 }

Write-Host "== smoke test ==" -ForegroundColor Cyan
& $exe --version
& $exe selftest
if ($LASTEXITCODE -ne 0) { Pop-Location; exit 1 }

$size = "{0:N1} MB" -f ((Get-Item $exe).Length / 1MB)
Write-Host "OK -> $exe ($size)" -ForegroundColor Green
Pop-Location
