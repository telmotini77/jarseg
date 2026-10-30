from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from app.agents.base import Agent, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.commands.apps import ApplicationService
from app.commands.base import CommandResult


class SystemAgent(Agent):
    def __init__(self, applications: ApplicationService, project_opener: Callable[[Path], CommandResult] | None = None) -> None:
        self.applications = applications
        self.project_opener = project_opener

    @property
    def name(self) -> str:
        return "system"

    @property
    def capabilities(self) -> set[str]:
        return {"system.open_application", "system.open_project"}

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if task.action == "system.open_application":
            target = str(task.parameters.get("application", ""))
            result = await asyncio.to_thread(self.applications.open, target)
        elif task.action == "system.open_project" and self.project_opener is not None:
            path = Path(str(task.parameters.get("path") or context.shared_state.get("active_project_path", "")))
            result = await asyncio.to_thread(self.project_opener, path)
        else:
            return AgentResult(task.id, self.name, False, summary="Acción de sistema no disponible.", error="unsupported_action")
        return AgentResult(task.id, self.name, result.success, {"message": result.message}, result.message, None if result.success else "system_failed")
