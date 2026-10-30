param(
    [switch]$OneFile
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

py -m pip install --disable-pip-version-check pyinstaller

$arguments = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--windowed",
    "--name", "JARVIS",
    "--workpath", "build-desktop",
    "--specpath", "build-desktop",
    "--hidden-import", "app.desktop.hud",
    "--hidden-import", "app.ui.panel"
)
if ($OneFile) {
    $arguments += "--onefile"
}
$arguments += "main.py"

& py @arguments
if ($LASTEXITCODE -ne 0) {
    throw "No se pudo empaquetar JARVIS Desktop."
}

if ($OneFile) {
    $output = "$PSScriptRoot\\dist\\JARVIS.exe"
} else {
    $output = "$PSScriptRoot\\dist\\JARVIS\\JARVIS.exe"
}
Write-Host "JARVIS Desktop listo en: $output"
Write-Host "Por seguridad, crea un .env junto al ejecutable; no se copia ningún secreto al paquete."
