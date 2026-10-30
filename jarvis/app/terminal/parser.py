from __future__ import annotations

import json
import re
import shlex
import unicodedata
from pathlib import Path

from app.security.permissions import SecurityLevel
from app.terminal.models import CommandSource, TerminalCommand
from app.terminal.security import classified


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text.casefold())
    return " ".join("".join(char for char in decomposed if unicodedata.category(char) != "Mn").split())


def package_scripts(directory: Path) -> dict[str, str]:
    file = directory / "package.json"
    if not file.is_file():
        return {}
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    scripts = data.get("scripts")
    return {str(key): str(value) for key, value in scripts.items()} if isinstance(scripts, dict) else {}


class TerminalParser:
    """Turns a small Spanish grammar into allow-listed structured commands."""

    def parse(self, text: str, cwd: Path, source: CommandSource = CommandSource.USER) -> TerminalCommand | None:
        raw = text.strip(" ¿?¡!.,")
        normalized = _normalize(raw)
        if normalized.startswith(("formatea", "format")):
            target = re.search(r"([a-zA-Z]:)", raw)
            return self._command("format", (target.group(1) if target else "C:",), cwd, source)
        if normalized.startswith(("diskpart", "borra todo", "elimina todo", "remove-item", "rmdir", "shutdown")):
            return self._command(normalized.split(" ", 1)[0], tuple(normalized.split(" ")[1:]), cwd, source)
        if match := re.match(r"^crea un commit con (?:el )?mensaje\s+[\"'](.+)[\"']$", raw, re.IGNORECASE):
            return self._command("git", ("commit", "-m", match.group(1)), cwd, source)
        if normalized in {"dime que version de python tengo", "dime mi version de python", "python version"}:
            return self._command("python", ("--version",), cwd, source)
        if normalized in {"dime que version de node tengo", "dime mi version de node", "node version"}:
            return self._command("node", ("--version",), cwd, source)
        if match := re.match(r"^dime si (.+) esta instalado$", normalized):
            tool = match.group(1).strip()
            return self._command(tool, ("--version",), cwd, source)
        if normalized in {"dime el estado del repositorio", "dime que archivos estan modificados"}:
            return self._command("git", ("status", "--short", "--branch"), cwd, source)
        if normalized in {"dime en que rama estoy", "en que rama estoy"}:
            return self._command("git", ("branch", "--show-current"), cwd, source)
        if normalized in {"muestrame los ultimos commits", "dime los ultimos commits"}:
            return self._command("git", ("log", "--oneline", "-5"), cwd, source)
        if match := re.match(r"^cambia a (?:la )?rama (.+)$", raw, re.IGNORECASE):
            return self._command("git", ("switch", match.group(1).strip()), cwd, source)
        if normalized in {"crea un entorno virtual", "crea el entorno virtual"}:
            return self._command("python", ("-m", "venv", ".venv"), cwd, source)
        if normalized in {"instala requirements.txt", "instala las dependencias", "instala dependencias"}:
            return self._command("python", ("-m", "pip", "install", "-r", "requirements.txt"), cwd, source)
        if normalized in {"ejecuta pytest", "ejecuta los tests", "ejecuta las pruebas"}:
            scripts = package_scripts(cwd)
            return self._command("npm", ("test",), cwd, source) if "test" in scripts else self._command("pytest", (), cwd, source)
        if normalized in {"dime que scripts tiene package.json", "dime que scripts tiene este proyecto"}:
            return None
        if normalized in {"inicia mi backend nestjs", "inicia el backend"}:
            scripts = package_scripts(cwd)
            return self._command("npm", ("run", "start:dev"), cwd, source) if "start:dev" in scripts else None
        if normalized in {"muestrame los procesos de node", "muestrame procesos de node"}:
            return self._command("tasklist", ("/FI", "IMAGENAME eq node.exe"), cwd, source)
        if normalized in {"dime si docker esta instalado", "docker esta instalado"}:
            return self._command("docker", ("--version",), cwd, source)
        direct = re.match(r"^(?:ejecuta|ejecutar|inicia)\s+(?:el comando\s+)?(.+)$", raw, re.IGNORECASE)
        if direct:
            return self._structured(direct.group(1), cwd, source)
        return None

    def _structured(self, raw: str, cwd: Path, source: CommandSource) -> TerminalCommand | None:
        try:
            parts = [part.strip("\"'") for part in shlex.split(raw, posix=False)]
        except ValueError:
            return self._command("", (), cwd, source)
        if not parts:
            return None
        if parts[0].casefold() == "git" and tuple(part.casefold() for part in parts[1:]) == ("status",):
            parts.extend(["--short", "--branch"])
        return self._command(parts[0], tuple(parts[1:]), cwd, source)

    @staticmethod
    def _command(executable: str, args: tuple[str, ...], cwd: Path, source: CommandSource) -> TerminalCommand:
        return classified(TerminalCommand(executable, args, cwd, SecurityLevel.RESTRICTED, True, source))
