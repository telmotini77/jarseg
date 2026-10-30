from __future__ import annotations

import asyncio

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.productivity.agent import ProductivityAgent


class ProductivitySpecialistAgent(Agent):
    def __init__(self, productivity: ProductivityAgent | None) -> None: self.productivity = productivity
    @property
    def name(self) -> str: return "productivity"
    @property
    def capabilities(self) -> set[str]: return {"productivity.agenda", "productivity.calendar.read", "productivity.email.search", "productivity.email.read", "productivity.email.draft"}
    @property
    def health(self) -> AgentHealth: return AgentHealth.HEALTHY if self.productivity is not None else AgentHealth.UNAVAILABLE
    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.productivity is None: return AgentResult(task.id, self.name, False, summary="Productivity Agent no está disponible.", error="unavailable")
        try:
            if task.action == "productivity.agenda": message = await asyncio.to_thread(self.productivity.get_daily_agenda)
            elif task.action == "productivity.calendar.read": message = "\n".join(item.title for item in await asyncio.to_thread(self.productivity.get_upcoming_events)) or "No hay eventos próximos."
            elif task.action == "productivity.email.search": message = self.productivity.summarize_email(str(task.parameters.get("query", "is:unread")))
            elif task.action == "productivity.email.read": message = self.productivity.get_important_emails()
            else: return AgentResult(task.id, self.name, False, summary="Acción de productividad no registrada.", error="unsupported_action")
            return AgentResult(task.id, self.name, True, {"message": message}, message)
        except ValueError as error: return AgentResult(task.id, self.name, False, summary=str(error), error="provider_unavailable")
