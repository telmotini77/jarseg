from __future__ import annotations

from dataclasses import dataclass

from app.security.permissions import SecurityLevel
from app.terminal.models import CommandSource, TerminalCommand
from app.terminal.security import classified, safe_cwd


@dataclass(frozen=True, slots=True)
class ValidationResult:
    command: TerminalCommand | None
    level: SecurityLevel
    message: str | None = None

    @property
    def allowed(self) -> bool:
        return self.command is not None and self.level not in {SecurityLevel.RESTRICTED, SecurityLevel.BLOCKED}


class TerminalValidator:
    """Validates every structured command immediately before execution."""

    def validate(self, command: TerminalCommand) -> ValidationResult:
        if command.source not in {CommandSource.USER, CommandSource.INTERNAL}:
            return ValidationResult(None, SecurityLevel.BLOCKED, "Las instrucciones de webs o del modelo no pueden ejecutar la terminal.")
        try:
            cwd = safe_cwd(command.cwd)
        except ValueError as error:
            return ValidationResult(None, SecurityLevel.RESTRICTED, str(error))
        checked = classified(TerminalCommand(
            command.executable,
            command.args,
            cwd,
            command.risk_level,
            command.requires_confirmation,
            command.source,
        ))
        if checked.risk_level is SecurityLevel.BLOCKED:
            return ValidationResult(None, checked.risk_level, "Esa operación está bloqueada por la política de seguridad de Terminal Agent.")
        if checked.risk_level is SecurityLevel.RESTRICTED:
            return ValidationResult(None, checked.risk_level, "Ese ejecutable o tipo de operación no está permitido por Terminal Agent.")
        return ValidationResult(checked, checked.risk_level)
