from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from app.automation.action import Action
from app.automation.action_queue import ActionQueue
from app.commands.base import CommandResult
from app.security.permissions import SecurityLevel
from app.terminal.context import TerminalContextInspector
from app.terminal.environment import EnvironmentInspector
from app.terminal.history import TerminalHistory
from app.terminal.models import ManagedProcess, TerminalCommand, TerminalCommandResult, TerminalMode
from app.terminal.process_manager import ProcessManager
from app.terminal.provider import TerminalProvider
from app.terminal.result_analyzer import diagnostic_context, summarize_result
from app.terminal.security import display_command
from app.terminal.validator import TerminalValidator
from app.terminal.working_directory import WorkingDirectoryManager


@dataclass(slots=True)
class TerminalManager:
    provider: TerminalProvider
    directories: WorkingDirectoryManager
    timeout: float = 60.0
    enabled: bool = True
    mode: TerminalMode = TerminalMode.CONFIRM
    allow_powershell: bool = True
    allow_cmd: bool = True
    managed_processes_enabled: bool = True
    history: TerminalHistory = field(default_factory=TerminalHistory)
    process_manager: ProcessManager = field(default_factory=ProcessManager)
    validator: TerminalValidator = field(default_factory=TerminalValidator)
    answerer: Callable[[list[dict[str, str]]], str] | None = None
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("jarvis.terminal"))
    memory: object | None = None
    _last_command: TerminalCommand | None = field(default=None, init=False, repr=False)
    _last_result: TerminalCommandResult | None = field(default=None, init=False, repr=False)
    _active_queue: ActionQueue | None = field(default=None, init=False, repr=False)
    _environment: EnvironmentInspector = field(init=False, repr=False)
    _context: TerminalContextInspector = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._environment = EnvironmentInspector(self.provider)
        self._context = TerminalContextInspector(self.provider, self.directories)

    @property
    def cwd(self) -> Path:
        return self.directories.current_directory

    def preview(self, command: TerminalCommand) -> CommandResult:
        checked = self.validator.validate(command)
        if not checked.allowed or checked.command is None:
            return CommandResult(False, checked.message or "El comando no pasó la validación.")
        return CommandResult(True, f"JARVIS ejecutaría:\n{display_command(checked.command)}\n\nDirectorio:\n{checked.command.cwd}\n\nRiesgo:\n{checked.level.name}\n\nNo he ejecutado ningún comando.")

    def execute(self, command: TerminalCommand) -> CommandResult:
        if not self.enabled:
            return CommandResult(False, "Terminal Agent está desactivado por configuración.")
        checked = self.validator.validate(command)
        if not checked.allowed or checked.command is None:
            return CommandResult(False, checked.message or "El comando no pasó la validación.")
        command = checked.command
        if self.mode is TerminalMode.READ_ONLY and command.risk_level is not SecurityLevel.SAFE:
            return CommandResult(False, "El modo terminal solo lectura no permite comandos que modifiquen el proyecto.")
        self.logger.info("TERMINAL command=%s args=%s risk=%s", command.executable, display_command(command), command.risk_level.name)
        if self.managed_processes_enabled and self.process_manager.is_long_running(command):
            try:
                process = self.process_manager.start_process(command, self._process_name(command))
            except OSError as error:
                return CommandResult(False, f"No pude iniciar el proceso administrado: {error}")
            return CommandResult(True, f"Proceso iniciado: {process.name}. PID: {process.pid}. ID: {process.id}.")
        result = self.provider.execute(command.argv, command.cwd, self.timeout)
        self._last_command, self._last_result = command, result
        self.history.add(command, result)
        self.logger.info("TERMINAL result=%s exit_code=%s duration=%.2f", "success" if result.success else "failure", result.exit_code, result.duration)
        message = summarize_result(command, result)
        if self.memory is not None:
            try:
                self.memory.remember_terminal_result(display_command(command), result.success, message)
            except Exception as error:
                self.logger.warning("MEMORY terminal bridge skipped reason=%s", type(error).__name__)
        return CommandResult(result.success, message)

    @staticmethod
    def _process_name(command: TerminalCommand) -> str:
        joined = " ".join((command.executable, *command.args)).casefold()
        if "start:dev" in joined or "nest" in joined:
            return "backend"
        if "vite" in joined or "ng serve" in joined:
            return "frontend"
        return " ".join(command.argv[:3])

    def execute_sequence(self, commands: tuple[TerminalCommand, ...]) -> CommandResult:
        if not commands:
            return CommandResult(False, "La secuencia de terminal está vacía.")
        queue = ActionQueue()
        for command in commands:
            checked = self.validator.validate(command)
            if not checked.allowed or checked.command is None:
                return CommandResult(False, checked.message or "La secuencia contiene un comando inválido.")
            queue.enqueue(Action("terminal_execute", parameters={"command": checked.command}, security_level=checked.level))
        self._active_queue = queue
        messages: list[str] = []
        while (action := queue.pop_next()) is not None:
            terminal_command = action.parameters.get("command")
            if not isinstance(terminal_command, TerminalCommand):
                queue.cancel()
                return CommandResult(False, "La secuencia contiene un comando inválido.")
            result = self.execute(terminal_command)
            if not result.success:
                queue.cancel()
                return CommandResult(False, f"{result.message} No ejecuté los pasos posteriores.")
            messages.append(result.message)
        return CommandResult(True, "\n".join(messages))

    def context(self) -> CommandResult:
        snapshot = self._context.inspect()
        project = snapshot.active_project or "sin proyecto activo"
        git = f"Git: rama {snapshot.git_branch or 'sin rama detectada'}" if snapshot.git_repository else "No es un repositorio Git."
        environment = snapshot.python_environment or "sin entorno virtual detectado"
        return CommandResult(True, f"Directorio actual: {snapshot.current_directory}\nProyecto: {project}\n{git}\nPython: {environment}")

    def change_directory(self, target: str) -> CommandResult:
        try:
            directory = self.directories.change_to(target)
            return CommandResult(True, f"Directorio de terminal: {directory}")
        except ValueError as error:
            return CommandResult(False, str(error))

    def parent_directory(self) -> CommandResult:
        try:
            return CommandResult(True, f"Directorio de terminal: {self.directories.parent()}")
        except ValueError as error:
            return CommandResult(False, str(error))

    def set_project(self, name: str) -> CommandResult:
        try:
            directory = self.directories.set_project(name)
            if self.memory is not None:
                try:
                    self.memory.index_project(str(directory), self.directories.active_project)
                except Exception as error:
                    self.logger.warning("MEMORY project bridge skipped reason=%s", type(error).__name__)
            return CommandResult(True, f"Proyecto activo: {self.directories.active_project}. Directorio: {directory}")
        except ValueError as error:
            return CommandResult(False, str(error))

    def set_mode(self, mode: TerminalMode) -> CommandResult:
        self.mode = mode
        labels = {TerminalMode.READ_ONLY: "solo lectura", TerminalMode.CONFIRM: "confirmación", TerminalMode.EXECUTE: "ejecución controlada"}
        return CommandResult(True, f"Modo terminal cambiado a {labels[mode]}.")

    def tool_status(self, tool: str) -> CommandResult:
        status = self._environment.status(tool, self.cwd)
        if not status.installed:
            return CommandResult(False, f"No encontré {status.name} en PATH.")
        version = f"\nVersión: {status.version}" if status.version else ""
        return CommandResult(True, f"{status.name} está instalado.{version}")

    def npm_scripts(self) -> CommandResult:
        package = self.cwd / "package.json"
        if not package.is_file():
            return CommandResult(False, "No encontré package.json en el directorio actual.")
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {})
        except (OSError, json.JSONDecodeError):
            return CommandResult(False, "No pude leer scripts válidos desde package.json.")
        if not isinstance(scripts, dict) or not scripts:
            return CommandResult(True, "package.json no define scripts.")
        return CommandResult(True, "Scripts disponibles:\n" + "\n".join(f"- {name}" for name in list(scripts)[:20]))

    def list_processes(self) -> CommandResult:
        processes = self.process_manager.list_managed_processes()
        if not processes:
            return CommandResult(True, "JARVIS no ha iniciado procesos administrados.")
        lines = [f"{item.id}. {item.name} — PID {item.pid} ({item.status})" for item in processes]
        return CommandResult(True, "Procesos administrados:\n" + "\n".join(lines))

    def process_output(self, identifier: str) -> CommandResult:
        output = self.process_manager.get_process_output(identifier)
        return CommandResult(True, "Salida reciente:\n" + "\n".join(output[-30:])) if output else CommandResult(False, "No encontré salida para un único proceso administrado.")

    def stop_process(self, identifier: str) -> CommandResult:
        process = self.process_manager.stop_process(identifier)
        return CommandResult(True, f"Deteniendo el proceso administrado {process.name}.") if process else CommandResult(False, "No encontré un único proceso administrado con ese nombre o ID.")

    def open_terminal_here(self) -> CommandResult:
        if not self.allow_powershell:
            return CommandResult(False, "PowerShell está desactivado para Terminal Agent.")
        escaped = str(self.cwd).replace("'", "''")
        try:
            subprocess.Popen(["powershell.exe", "-NoExit", "-Command", f"Set-Location -LiteralPath '{escaped}'"], shell=False)
        except OSError as error:
            return CommandResult(False, f"No pude abrir PowerShell: {error}")
        return CommandResult(True, f"Abrí PowerShell en {self.cwd}.")

    def diagnose(self) -> CommandResult:
        context = diagnostic_context(self._last_command, self._last_result)
        if self.answerer is None:
            return CommandResult(True, context)
        try:
            return CommandResult(True, self.answerer([{"role": "user", "content": context}]))
        except Exception:
            return CommandResult(False, "No pude analizar el último error de terminal.")

    def last_output(self) -> CommandResult:
        if self._last_result is None:
            return CommandResult(False, "No hay salida de terminal reciente.")
        output = self._last_result.stderr or self._last_result.stdout
        return CommandResult(True, output[-8_000:] or "El último comando no produjo salida.")

    def cancel_pending_actions(self) -> None:
        if self._active_queue is not None:
            self._active_queue.cancel()
