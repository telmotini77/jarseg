from __future__ import annotations

from app.agents.base import AgentTask
from app.agents.context import AgentContext
from app.agents.registry import AgentRegistry
from app.agents.result import AgentResult
from app.automation_engine.models import Automation, AutomationRun
from app.events.bus import EventBus
from app.events.models import JarvisEvent


class AutomationExecutor:
    def __init__(self, agents: AgentRegistry, events: EventBus, notifier=None) -> None:
        self.agents, self.events, self.notifier = agents, events, notifier

    async def execute(self, automation: Automation, context: AgentContext, *, automatic: bool) -> AutomationRun:
        summaries: list[str] = []
        for action in automation.actions:
            if action.action == "notify":
                message = str(action.parameters.get("message", f"Automatización {automation.name} activada."))
                self.events.publish(JarvisEvent("NOTIFICATION", "automation", {"message": message}, context.session_id))
                if self.notifier:
                    self.notifier(message)
                summaries.append(message)
                continue
            if automatic and action.risk_level != "safe":
                return AutomationRun(automation.id, False, "La política actual exige confirmación para esta acción automática.", error="policy_rejected")
            task = AgentTask(action.agent, action.action, f"Automatización {automation.name}", action.parameters, risk_level=action.risk_level, resources=(f"automation:{automation.id}",))
            result: AgentResult = await self.agents.get(action.agent).execute(task, context)
            summaries.append(result.summary)
            if not result.success:
                return AutomationRun(automation.id, False, result.summary, {"action": action.action}, result.error)
        return AutomationRun(automation.id, True, "\n".join(summaries) or f"Automatización {automation.name} ejecutada.")
