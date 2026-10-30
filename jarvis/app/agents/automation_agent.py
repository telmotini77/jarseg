from __future__ import annotations

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult


class AutomationAgent(Agent):
    def __init__(self, engine: object | None) -> None:
        self.engine = engine

    @property
    def name(self) -> str:
        return "automation"

    @property
    def capabilities(self) -> set[str]:
        return {"automation.create", "automation.list", "automation.enable", "automation.disable", "automation.run"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.engine is not None else AgentHealth.UNAVAILABLE

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.engine is None:
            return AgentResult(task.id, self.name, False, summary="Automation Engine no está disponible.", error="unavailable")
        try:
            if task.action == "automation.list":
                items = self.engine.list()
                return AgentResult(task.id, self.name, True, {"automations": items}, f"Hay {len(items)} automatizaciones.")
            if task.action == "automation.disable":
                changed = self.engine.set_enabled(str(task.parameters["id"]), False)
                return AgentResult(task.id, self.name, changed, {"changed": changed}, "Automatización desactivada." if changed else "No encontré la automatización.")
            if task.action == "automation.enable":
                changed = self.engine.set_enabled(str(task.parameters["id"]), True)
                return AgentResult(task.id, self.name, changed, {"changed": changed}, "Automatización activada." if changed else "No encontré la automatización.")
            if task.action == "automation.run":
                result = await self.engine.run_manual(str(task.parameters["id"]), context)
                return AgentResult(task.id, self.name, result.success, result.data, result.summary, result.error)
        except (KeyError, ValueError) as error:
            return AgentResult(task.id, self.name, False, summary=str(error), error="automation_failed")
        return AgentResult(task.id, self.name, False, summary="Acción de automatización no registrada.", error="unsupported_action")
