from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.commands.base import CommandResult
from app.terminal.manager import TerminalManager


class TerminalAgent(Agent):
    def __init__(self, terminal: TerminalManager | None, test_runner: Callable[[Path], str] | None = None, backend_runner: Callable[[Path], CommandResult] | None = None) -> None:
        self.terminal, self.test_runner, self.backend_runner = terminal, test_runner, backend_runner

    @property
    def name(self) -> str:
        return "terminal"

    @property
    def capabilities(self) -> set[str]:
        return {"terminal.run_tests", "terminal.start_backend", "terminal.status"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.terminal is not None else AgentHealth.UNAVAILABLE

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.terminal is None:
            return AgentResult(task.id, self.name, False, summary="Terminal Agent no está disponible.", error="unavailable")
        path = Path(str(task.parameters.get("path") or context.shared_state.get("active_project_path", self.terminal.cwd)))
        if task.action == "terminal.run_tests" and self.test_runner is not None:
            message = await asyncio.to_thread(self.test_runner, path)
            success = "fall" not in message.casefold() and "error" not in message.casefold()
            return AgentResult(task.id, self.name, success, {"output": message, "path": str(path)}, message, None if success else "tests_failed")
        if task.action == "terminal.start_backend" and self.backend_runner is not None:
            result = await asyncio.to_thread(self.backend_runner, path)
            return AgentResult(task.id, self.name, result.success, {"message": result.message}, result.message, None if result.success else "backend_failed")
        if task.action == "terminal.status":
            result = await asyncio.to_thread(self.terminal.context)
            return AgentResult(task.id, self.name, result.success, {"message": result.message}, result.message)
        return AgentResult(task.id, self.name, False, summary="Acción de terminal no registrada.", error="unsupported_action")
