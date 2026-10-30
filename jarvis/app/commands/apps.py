from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from os import environ
from pathlib import Path
from shutil import which

from app.commands.base import CommandResult
from app.commands.classifier import normalize_text


@dataclass(frozen=True, slots=True)
class ApplicationSpec:
    key: str
    display_name: str
    launch_commands: tuple[tuple[str, ...], ...]
    process_name: str | None


@dataclass(frozen=True, slots=True)
class InstalledApplication:
    """Aplicación descubierta desde fuentes locales confiables de Windows."""

    name: str
    path: Path
    launch_kind: str  # executable o shortcut


APPLICATIONS: dict[str, ApplicationSpec] = {
    "vscode": ApplicationSpec("vscode", "Visual Studio Code", (("code",), ("Code.exe",)), "Code.exe"),
    "chrome": ApplicationSpec("chrome", "Google Chrome", (("chrome.exe",),), "chrome.exe"),
    "edge": ApplicationSpec("edge", "Microsoft Edge", (("msedge.exe",),), "msedge.exe"),
    "notepad": ApplicationSpec("notepad", "Bloc de notas", (("notepad.exe",),), "notepad.exe"),
    "calculator": ApplicationSpec("calculator", "Calculadora", (("calc.exe",),), "CalculatorApp.exe"),
    "explorer": ApplicationSpec("explorer", "Explorador de archivos", (("explorer.exe",),), "explorer.exe"),
    "terminal": ApplicationSpec("terminal", "Terminal", (("wt.exe",),), "WindowsTerminal.exe"),
    "arduino": ApplicationSpec("arduino", "Arduino IDE", (("arduino-ide.exe",), ("arduino.exe",)), "Arduino IDE.exe"),
    "docker": ApplicationSpec("docker", "Docker Desktop", (("Docker Desktop.exe",),), "Docker Desktop.exe"),
    "spotify": ApplicationSpec("spotify", "Spotify", (("spotify.exe",),), "Spotify.exe"),
}

APP_ALIASES: dict[str, str] = {
    "vscode": "vscode", "vs code": "vscode", "visual studio code": "vscode",
    "chrome": "chrome", "google chrome": "chrome",
    "edge": "edge", "microsoft edge": "edge",
    "bloc de notas": "notepad", "notepad": "notepad",
    "calculadora": "calculator", "calculator": "calculator",
    "explorador de archivos": "explorer", "explorador": "explorer",
    "terminal": "terminal", "windows terminal": "terminal",
    "arduino": "arduino", "arduino ide": "arduino",
    "docker": "docker", "docker desktop": "docker",
    "spotify": "spotify",
}

_CHROME_PROFILE_PATTERN = re.compile(r"^(?:Default|Profile [0-9]+)$")


def resolve_application(target: str | None) -> ApplicationSpec | None:
    if not target:
        return None
    key = APP_ALIASES.get(normalize_text(target))
    return APPLICATIONS.get(key) if key else None


def _start_menu_roots() -> tuple[Path, ...]:
    roots = (
        environ.get("APPDATA", ""),
        environ.get("ProgramData", ""),
    )
    return tuple(
        Path(root) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        for root in roots
        if root
    )


def _start_menu_applications() -> list[InstalledApplication]:
    applications: list[InstalledApplication] = []
    for root in _start_menu_roots():
        if not root.is_dir():
            continue
        try:
            entries = root.rglob("*")
            for entry in entries:
                if not entry.is_file() or entry.suffix.casefold() not in {".lnk", ".appref-ms"}:
                    continue
                label = entry.stem.replace("_", " ").strip()
                if label:
                    applications.append(InstalledApplication(label, entry, "shortcut"))
                if len(applications) >= 2_000:
                    return applications
        except OSError:
            continue
    return applications


def _registry_applications() -> list[InstalledApplication]:
    """Enumera solo App Paths de Windows; no interpreta texto proporcionado por voz."""
    if platform.system() != "Windows":
        return []
    try:
        import winreg
    except ImportError:
        return []
    applications: list[InstalledApplication] = []
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, base) as parent:
                index = 0
                while True:
                    try:
                        executable = winreg.EnumKey(parent, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(parent, executable) as key:
                            value, _ = winreg.QueryValueEx(key, "")
                        candidate = Path(str(value).strip().strip('"'))
                        if candidate.is_file() and candidate.suffix.casefold() == ".exe":
                            applications.append(InstalledApplication(candidate.stem, candidate, "executable"))
                    except OSError:
                        continue
        except OSError:
            continue
    return applications


def discover_installed_applications() -> list[InstalledApplication]:
    """Catálogo local de aplicaciones iniciables, deduplicado y sin escanear discos."""
    if platform.system() != "Windows":
        return []
    discovered: dict[tuple[str, str], InstalledApplication] = {}
    for application in [*_registry_applications(), *_start_menu_applications()]:
        key = (normalize_text(application.name), str(application.path).casefold())
        discovered[key] = application
    return sorted(discovered.values(), key=lambda item: normalize_text(item.name))


def resolve_discovered_application(target: str | None, catalog: list[InstalledApplication]) -> InstalledApplication | None:
    if not target:
        return None
    query = normalize_text(target)
    exact = [item for item in catalog if normalize_text(item.name) == query or normalize_text(item.path.stem) == query]
    if len(exact) == 1:
        return exact[0]
    # Se permiten coincidencias parciales solo cuando son inequívocas.
    matches = [item for item in catalog if query in normalize_text(item.name) or normalize_text(item.name) in query]
    return matches[0] if len(matches) == 1 else None


def _registered_windows_app(executable: str) -> str | None:
    """Resolve a trusted executable from Windows' App Paths registry entries."""
    if platform.system() != "Windows":
        return None
    try:
        import winreg

        subkey = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{executable}"
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    value, _ = winreg.QueryValueEx(key, "")
                candidate = Path(str(value).strip().strip('"'))
                if candidate.is_file():
                    return str(candidate)
            except OSError:
                continue
    except ImportError:
        return None
    return None


def _standard_windows_app(executable: str) -> str | None:
    """Search only known system/user installation roots, never user-provided paths."""
    relative_paths: dict[str, tuple[str, ...]] = {
        "chrome.exe": ("Google", "Chrome", "Application", "chrome.exe"),
        "msedge.exe": ("Microsoft", "Edge", "Application", "msedge.exe"),
        "Code.exe": ("Microsoft VS Code", "Code.exe"),
        "spotify.exe": ("Spotify", "Spotify.exe"),
    }
    parts = relative_paths.get(executable)
    if parts is None:
        return None
    roots = [
        environ.get("ProgramFiles", ""),
        environ.get("ProgramFiles(x86)", ""),
        environ.get("LOCALAPPDATA", ""),
    ]
    for root in filter(None, roots):
        candidate = Path(root).joinpath(*parts)
        if candidate.is_file():
            return str(candidate)
        if executable == "Code.exe":
            local_candidate = Path(root) / "Programs" / candidate.relative_to(root)
            if local_candidate.is_file():
                return str(local_candidate)
    return None


def resolve_launch_command(command: tuple[str, ...]) -> tuple[str, ...] | None:
    executable = command[0]
    located = which(executable) or _registered_windows_app(executable) or _standard_windows_app(executable)
    if located:
        return (located, *command[1:])
    if executable.lower() in {"calc.exe", "notepad.exe", "explorer.exe"}:
        return command
    return None


def last_used_chrome_profile(user_data_dir: Path | None = None) -> str | None:
    """Read Chrome's profile choice without accessing account data or cookies."""
    directory = user_data_dir
    if directory is None:
        local_app_data = environ.get("LOCALAPPDATA", "")
        if not local_app_data:
            return None
        directory = Path(local_app_data) / "Google" / "Chrome" / "User Data"
    try:
        state = json.loads((directory / "Local State").read_text(encoding="utf-8"))
        profile = state.get("profile", {}).get("last_used", "")
    except (OSError, json.JSONDecodeError, AttributeError):
        return None
    return profile if isinstance(profile, str) and _CHROME_PROFILE_PATTERN.fullmatch(profile) else None


def resolve_chrome_launch_command(
    chrome_profile: str = "last_used", url: str | None = None
) -> tuple[str, ...] | None:
    """Resolve Chrome and select a local profile so its existing session is used."""
    command = resolve_launch_command(("chrome.exe",))
    if command is None:
        return None
    profile = last_used_chrome_profile() if chrome_profile == "last_used" else chrome_profile
    arguments = list(command)
    if profile:
        arguments.append(f"--profile-directory={profile}")
    if url:
        arguments.append(url)
    return tuple(arguments)


class ApplicationService:
    def __init__(self, chrome_profile: str = "last_used") -> None:
        self._chrome_profile = chrome_profile
        self._catalog: list[InstalledApplication] | None = None

    def list_available(self, query: str | None = None) -> CommandResult:
        if platform.system() != "Windows":
            return CommandResult(False, "Buscar aplicaciones instaladas solo está disponible en Windows.")
        catalog = self._installed_catalog()
        if query:
            normalized = normalize_text(query)
            catalog = [item for item in catalog if normalized in normalize_text(item.name)]
        if not catalog:
            return CommandResult(False, "No encontré aplicaciones instaladas que coincidan.")
        labels = []
        seen: set[str] = set()
        for item in catalog:
            label = item.name
            key = normalize_text(label)
            if key not in seen:
                seen.add(key)
                labels.append(label)
            if len(labels) == 30:
                break
        return CommandResult(True, "Aplicaciones disponibles:\n" + "\n".join(f"- {label}" for label in labels))

    def refresh_catalog(self) -> None:
        self._catalog = discover_installed_applications()

    def _installed_catalog(self) -> list[InstalledApplication]:
        if self._catalog is None:
            self.refresh_catalog()
        return self._catalog or []

    def open(self, target: str | None) -> CommandResult:
        application = resolve_application(target)
        if platform.system() != "Windows":
            return CommandResult(False, "Abrir aplicaciones solo está disponible en Windows.")
        if application is None:
            discovered = resolve_discovered_application(target, self._installed_catalog())
            if discovered is None:
                return CommandResult(False, "No encontré esa aplicación instalada. Di 'Jarvis muestra aplicaciones disponibles' para consultar el catálogo local.")
            try:
                if discovered.launch_kind == "shortcut":
                    os.startfile(str(discovered.path))
                else:
                    subprocess.Popen([str(discovered.path)], shell=False)
                return CommandResult(True, f"Abriendo {discovered.name}.")
            except OSError as error:
                return CommandResult(False, f"Windows no pudo abrir {discovered.name}: {error}")
        for command in application.launch_commands:
            resolved_command = (
                resolve_chrome_launch_command(self._chrome_profile)
                if application.key == "chrome"
                else resolve_launch_command(command)
            )
            if resolved_command:
                try:
                    subprocess.Popen(list(resolved_command), shell=False)
                    return CommandResult(True, f"Abriendo {application.display_name}.")
                except OSError:
                    continue
        return CommandResult(False, f"No encontré {application.display_name} en este equipo.")

    def close(self, target: str | None) -> CommandResult:
        application = resolve_application(target)
        if application is None or not application.process_name:
            return CommandResult(False, "Esa aplicación no está registrada para cerrarse de forma segura.")
        if platform.system() != "Windows":
            return CommandResult(False, "Cerrar aplicaciones solo está disponible en Windows.")
        try:
            completed = subprocess.run(
                ["taskkill", "/IM", application.process_name, "/T"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return CommandResult(False, "No fue posible comunicarse con Windows para cerrar la aplicación.")
        if completed.returncode == 0:
            return CommandResult(True, f"Cerré {application.display_name}.")
        return CommandResult(False, f"{application.display_name} no está abierta o Windows no permitió cerrarla.")
