from __future__ import annotations

from app.agents.base import Agent, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult


class ConversationAgent(Agent):
    @property
    def name(self) -> str:
        return "conversation"

    @property
    def capabilities(self) -> set[str]:
        return {"conversation.summarize"}

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        items = context.shared_state.get("task_results", {})
        summaries = [value.summary for value in items.values() if getattr(value, "summary", "")]
        summary = "\n".join(f"- {item}" for item in summaries[-6:]) or "No hubo resultados previos para resumir."
        return AgentResult(task.id, self.name, True, {"items": len(summaries)}, summary)
