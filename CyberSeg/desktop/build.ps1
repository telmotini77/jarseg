# Builds dist\CyberSeg.exe: a single file, no console window.
#   powershell -ExecutionPolicy Bypass -File desktop\build.ps1
# Copy the result to the server's downloads\ folder to offer it from the web panel.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path .build-venv)) { python -m venv .build-venv }
& .\.build-venv\Scripts\python.exe -m pip install --quiet --disable-pip-version-check pyinstaller==6.16.0
& .\.build-venv\Scripts\pyinstaller.exe --noconfirm --clean --onefile --windowed `
  --name CyberSeg --icon cyberseg.ico --add-data "cyberseg.ico;." cyberseg_desktop.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falló ($LASTEXITCODE)" }
Write-Host "Listo: $PSScriptRoot\dist\CyberSeg.exe"
