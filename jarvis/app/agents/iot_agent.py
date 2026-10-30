from __future__ import annotations

import asyncio

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.iot.agent import IoTAgent


class IoTSpecialistAgent(Agent):
    def __init__(self, iot: IoTAgent | None) -> None:
        self.iot = iot

    @property
    def name(self) -> str:
        return "iot"

    @property
    def capabilities(self) -> set[str]:
        return {"iot.read", "iot.list_devices", "iot.create_rule", "iot.disable_rules"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.iot is not None else AgentHealth.DEGRADED

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.iot is None:
            return AgentResult(task.id, self.name, False, summary="IoT Agent no está disponible.", error="unavailable")
        try:
            if task.action == "iot.read":
                message = await asyncio.to_thread(self.iot.get_device_state, task.parameters.get("device"))
            elif task.action == "iot.list_devices":
                message = await asyncio.to_thread(self.iot.list_devices)
            elif task.action == "iot.create_rule":
                message = await asyncio.to_thread(self.iot.create_rule, task.parameters.get("device"), str(task.parameters["sensor"]), str(task.parameters["operator"]), float(task.parameters["threshold"]), str(task.parameters.get("action", "notify")))
            elif task.action == "iot.disable_rules":
                message = await asyncio.to_thread(self.iot.disable_rules, task.parameters.get("device"), task.parameters.get("sensor"))
            else:
                return AgentResult(task.id, self.name, False, summary="Acción IoT no registrada.", error="unsupported_action")
            return AgentResult(task.id, self.name, True, {"message": message}, message)
        except (ConnectionError, ValueError, RuntimeError) as error:
            return AgentResult(task.id, self.name, False, summary=str(error), error="iot_failed")
