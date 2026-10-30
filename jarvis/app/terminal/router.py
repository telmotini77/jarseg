from __future__ import annotations

import re

from app.commands.base import Command, CommandResult
from app.commands.classifier import normalize_text
from app.terminal.manager import TerminalManager
from app.terminal.models import CommandSource, TerminalCommand, TerminalMode
from app.terminal.parser import TerminalParser


class TerminalRouter:
    def __init__(self, manager: TerminalManager) -> None:
        self._manager = manager
        self._parser = TerminalParser()
        self.handlers = {
            "terminal_execute": self._execute,
            "terminal_sequence": self._sequence,
            "terminal_preview": self._preview,
            "terminal_context": lambda _command: self._manager.context(),
            "terminal_change_directory": lambda command: self._manager.change_directory(command.target or ""),
            "terminal_parent_directory": lambda _command: self._manager.parent_directory(),
            "terminal_set_project": lambda command: self._manager.set_project(command.target or ""),
            "terminal_set_mode": self._set_mode,
            "terminal_tool_status": lambda command: self._manager.tool_status(command.target or ""),
            "terminal_npm_scripts": lambda _command: self._manager.npm_scripts(),
            "terminal_list_processes": lambda _command: self._manager.list_processes(),
            "terminal_process_output": lambda command: self._manager.process_output(command.target or ""),
            "terminal_stop_process": lambda command: self._manager.stop_process(command.target or ""),
            "terminal_open_here": lambda _command: self._manager.open_terminal_here(),
            "terminal_diagnose": lambda _command: self._manager.diagnose(),
            "terminal_last_output": lambda _command: self._manager.last_output(),
        }

    def parse(self, raw: str, cleaned: str | None = None) -> Command | None:
        normalized = cleaned or normalize_text(raw)
        if normalized in {"dime donde estoy", "donde estoy"}:
            return Command("terminal_context")
        if normalized in {"vuelve una carpeta", "vuelve a la carpeta anterior"}:
            return Command("terminal_parent_directory")
        if normalized in {"abre la terminal aqui", "abre powershell en mi proyecto", "abre powershell aqui"}:
            return Command("terminal_open_here")
        if normalized in {"dime que procesos has iniciado", "dime que procesos inicio jarvis"}:
            return Command("terminal_list_processes")
        if match := re.match(r"^(?:muestrame|dime) la salida (?:de|del)\s+(.+)$", normalized, re.IGNORECASE):
            return Command("terminal_process_output", target=match.group(1).strip())
        if normalized in {"diagnostica este error", "diagnostica el ultimo error"}:
            return Command("terminal_diagnose")
        if normalized in {"muestrame el error completo", "muestrame la salida completa"}:
            return Command("terminal_last_output")
        if normalized in {"dime que scripts tiene package.json", "dime que scripts tiene este proyecto"}:
            return Command("terminal_npm_scripts")
        if match := re.match(r"^(?:entra a|ve a)\s+(.+)$", raw, re.IGNORECASE):
            return Command("terminal_change_directory", target=match.group(1).strip())
        if match := re.match(r"^(?:cambia al proyecto|establece)\s+(.+?)(?: como proyecto actual)?$", raw, re.IGNORECASE):
            return Command("terminal_set_project", target=match.group(1).strip())
        if match := re.match(r"^det(?:en|én)\s+(?:el )?(.+)$", raw, re.IGNORECASE):
            return Command("terminal_stop_process", target=match.group(1).strip())
        if normalized in {"activa modo solo lectura", "modo solo lectura"}:
            return Command("terminal_set_mode", target=TerminalMode.READ_ONLY.value)
        if normalized in {"activa modo confirmacion", "modo confirmacion"}:
            return Command("terminal_set_mode", target=TerminalMode.CONFIRM.value)
        if normalized in {"activa modo ejecucion", "modo ejecucion"}:
            return Command("terminal_set_mode", target=TerminalMode.EXECUTE.value)
        if preview := re.match(r"^(?:dime )?que harias con (.+?) pero no lo ejecutes$", normalized, re.IGNORECASE):
            command = self._parser.parse(f"ejecuta {preview.group(1)}", self._manager.cwd)
            return Command("terminal_preview", arguments={"terminal_command": command}) if command else None
        chain = re.match(r"^instala (?:las )?dependencias y ejecuta (?:los )?tests$", normalized)
        if chain:
            install = self._parser.parse("instala las dependencias", self._manager.cwd)
            tests = self._parser.parse("ejecuta los tests", self._manager.cwd)
            return Command("terminal_sequence", arguments={"terminal_commands": tuple(item for item in (install, tests) if item is not None)})
        command = self._parser.parse(raw, self._manager.cwd, CommandSource.USER)
        return Command("terminal_execute", arguments={"terminal_command": command}) if command else None

    def _execute(self, command: Command) -> CommandResult:
        terminal = command.arguments.get("terminal_command")
        return self._manager.execute(terminal) if isinstance(terminal, TerminalCommand) else CommandResult(False, "No entendí un comando de terminal estructurado.")

    def _sequence(self, command: Command) -> CommandResult:
        commands = command.arguments.get("terminal_commands")
        return self._manager.execute_sequence(commands) if isinstance(commands, tuple) and all(isinstance(item, TerminalCommand) for item in commands) else CommandResult(False, "La secuencia de terminal no es válida.")

    def _preview(self, command: Command) -> CommandResult:
        terminal = command.arguments.get("terminal_command")
        return self._manager.preview(terminal) if isinstance(terminal, TerminalCommand) else CommandResult(False, "No entendí el comando para previsualizar.")

    def _set_mode(self, command: Command) -> CommandResult:
        try:
            return self._manager.set_mode(TerminalMode(command.target or ""))
        except ValueError:
            return CommandResult(False, "Indica un modo de terminal válido.")

    def cancel_pending_actions(self) -> None:
        self._manager.cancel_pending_actions()
