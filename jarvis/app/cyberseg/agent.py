from __future__ import annotations

import asyncio

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.cyberseg.client import CyberSegClient, CyberSegClientError
from app.cyberseg.threat_intelligence import coverage_report, enrich_alerts


class CyberSegAgent(Agent):
    """Registered, allow-listed CyberSeg operations for the orchestrator."""

    def __init__(self, client: CyberSegClient | None) -> None:
        self.client = client

    @property
    def name(self) -> str:
        return "cyberseg"

    @property
    def capabilities(self) -> set[str]:
        return {"cyberseg.status", "cyberseg.alerts", "cyberseg.threat_coverage", "cyberseg.start_capture", "cyberseg.stop_capture"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.client is not None else AgentHealth.DEGRADED

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.client is None:
            return AgentResult(task.id, self.name, False, summary="CyberSeg no está conectado.", error="unavailable")
        try:
            if task.action == "cyberseg.status":
                message = await asyncio.to_thread(self.client.status)
            elif task.action == "cyberseg.alerts":
                message = enrich_alerts(await asyncio.to_thread(self.client.recent_alerts, int(task.parameters.get("limit", 5))))
            elif task.action == "cyberseg.threat_coverage":
                message = coverage_report()
            elif task.action == "cyberseg.start_capture":
                message = await asyncio.to_thread(self.client.start_capture)
            elif task.action == "cyberseg.stop_capture":
                message = await asyncio.to_thread(self.client.stop_capture)
            else:
                return AgentResult(task.id, self.name, False, summary="Acción CyberSeg no registrada.", error="unsupported_action")
            return AgentResult(task.id, self.name, True, {"message": message}, message)
        except (CyberSegClientError, ValueError) as error:
            return AgentResult(task.id, self.name, False, summary=str(error), error="cyberseg_failed")
