from __future__ import annotations

import asyncio

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.browser.browser_manager import BrowserManager


class BrowserAgent(Agent):
    def __init__(self, browser: BrowserManager | None) -> None:
        self.browser = browser

    @property
    def name(self) -> str:
        return "browser"

    @property
    def capabilities(self) -> set[str]:
        return {"browser.search", "browser.open", "browser.read"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.browser is not None else AgentHealth.UNAVAILABLE

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.browser is None:
            return AgentResult(task.id, self.name, False, summary="Browser Agent no está disponible.", error="unavailable")
        if task.action == "browser.search":
            result = await asyncio.to_thread(self.browser.search, str(task.parameters.get("query", task.objective)))
        elif task.action == "browser.open":
            result = await asyncio.to_thread(self.browser.open, str(task.parameters.get("target", "")))
        elif task.action == "browser.read":
            result = await asyncio.to_thread(self.browser.read_page)
        else:
            return AgentResult(task.id, self.name, False, summary="Acción de navegador no registrada.", error="unsupported_action")
        return AgentResult(task.id, self.name, result.success, {"message": result.message}, result.message, None if result.success else "browser_failed")
