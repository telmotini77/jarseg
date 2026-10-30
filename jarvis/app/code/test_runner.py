from __future__ import annotations

from app.code.models import ProjectContext
from app.code.validator import CodeValidator
from app.security.permissions import SecurityLevel
from app.terminal.manager import TerminalManager
from app.terminal.models import CommandSource, TerminalCommand
from app.terminal.security import classified


class CodeTestRunner:
    """Ejecuta validaciones exclusivamente a través de Terminal Agent."""

    def __init__(self, terminal: TerminalManager, validator: CodeValidator | None = None) -> None:
        self.terminal = terminal
        self.validator = validator or CodeValidator()

    def run(self, project: ProjectContext, kind: str = "tests") -> str:
        plan = self.validator.available(project)
        selected = [(command, label) for command, label in zip(plan.commands, plan.labels) if kind in {"all", label, "tests" if label == "tests" else ""}]
        if not selected:
            return f"No encontré un comando de {kind} compatible en este proyecto."
        messages: list[str] = []
        for argv, label in selected:
            command = classified(TerminalCommand(argv[0], tuple(argv[1:]), project.root_path, SecurityLevel.CONFIRMATION, True, CommandSource.INTERNAL))
            result = self.terminal.execute(command)
            messages.append(f"{label}: {result.message}")
            if not result.success:
                break
        return "\n".join(messages)
