from __future__ import annotations

import asyncio

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.vision.service import VisionService


class VisionAgent(Agent):
    def __init__(self, vision: VisionService | None) -> None:
        self.vision = vision

    @property
    def name(self) -> str:
        return "vision"

    @property
    def capabilities(self) -> set[str]:
        return {"vision.capture", "vision.analyze"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.vision is not None else AgentHealth.UNAVAILABLE

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.vision is None:
            return AgentResult(task.id, self.name, False, summary="Vision Agent no está disponible.", error="unavailable")
        if task.action == "vision.capture":
            result = await asyncio.to_thread(self.vision.capture_screen)
        elif task.action == "vision.analyze":
            result = await asyncio.to_thread(self.vision.analyze_screen, str(task.parameters.get("question", context.user_goal)))
        else:
            return AgentResult(task.id, self.name, False, summary="Acción visual no registrada.", error="unsupported_action")
        return AgentResult(task.id, self.name, result.success, {"message": result.message}, result.message, None if result.success else "vision_failed")
