from __future__ import annotations

from pathlib import Path

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.memory.manager import MemoryManager
from app.memory.project_memory import slugify


class MemoryAgent(Agent):
    def __init__(self, memory: MemoryManager | None) -> None:
        self.memory = memory

    @property
    def name(self) -> str:
        return "memory"

    @property
    def capabilities(self) -> set[str]:
        return {"memory.resolve_project", "memory.recall", "memory.store_episode"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.memory is not None else AgentHealth.DEGRADED

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.memory is None:
            return AgentResult(task.id, self.name, False, summary="Memory Engine no está disponible.", error="unavailable")
        if task.action == "memory.resolve_project":
            requested = str(task.parameters.get("project", "")).strip()
            project = self.memory.repository.get_project(slugify(requested)) if requested else None
            if project is None:
                matches = [item for item in self.memory.repository.list_projects() if requested.casefold() in {item.name.casefold(), item.id.casefold()}]
                project = matches[0] if len(matches) == 1 else None
            if project is None or not Path(project.root_path).is_dir():
                return AgentResult(task.id, self.name, False, summary=f"No localicé el proyecto {requested} en memoria.", error="project_not_found")
            context.active_project = project.name
            context.shared_state["active_project_path"] = project.root_path
            return AgentResult(task.id, self.name, True, {"project": project.name, "path": project.root_path}, f"Proyecto {project.name} localizado.")
        if task.action == "memory.recall":
            query = str(task.parameters.get("query", context.user_goal))
            items = self.memory.recall(query)
            return AgentResult(task.id, self.name, True, {"memories": [item.content for item in items]}, f"Recuperé {len(items)} recuerdos relevantes.")
        if task.action == "memory.store_episode":
            text = str(task.parameters.get("summary", "")).strip()
            stored = self.memory.remember(text, "conversation", source="system", importance=0.55) if text else None
            return AgentResult(task.id, self.name, stored is not None, {"stored": bool(stored)}, "Resumen de tarea guardado." if stored else "No guardé un resumen persistente.")
        return AgentResult(task.id, self.name, False, summary="Acción de memoria no registrada.", error="unsupported_action")
