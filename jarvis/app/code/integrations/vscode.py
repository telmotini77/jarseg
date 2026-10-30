from __future__ import annotations

from pathlib import Path
from shutil import which

from app.commands.base import CommandResult
from app.security.permissions import SecurityLevel
from app.terminal.manager import TerminalManager
from app.terminal.models import CommandSource, TerminalCommand
from app.terminal.security import classified


class VSCodeIntegration:
    def __init__(self, terminal: TerminalManager, enabled: bool = True) -> None:
        self.terminal = terminal
        self.enabled = enabled

    def available(self) -> bool:
        return self.enabled and which("code") is not None

    def open_project(self, root: Path) -> CommandResult:
        if not self.available():
            return CommandResult(False, "No encontré el comando `code` en PATH.")
        return self._execute((str(root),), root)

    def open_file(self, path: Path, root: Path, line: int | None = None) -> CommandResult:
        if not self.available():
            return CommandResult(False, "No encontré el comando `code` en PATH.")
        target = f"{path}:{line}" if line else str(path)
        return self._execute(("-g", target) if line else (target,), root)

    def _execute(self, args: tuple[str, ...], root: Path) -> CommandResult:
        command = classified(TerminalCommand("code", args, root, SecurityLevel.CONFIRMATION, True, CommandSource.INTERNAL))
        return self.terminal.execute(command)
