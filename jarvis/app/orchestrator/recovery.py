from __future__ import annotations

from app.agents.base import AgentTask


class RecoveryManager:
    def __init__(self, max_retries: int = 2) -> None:
        self.max_retries = max_retries

    def may_retry(self, task: AgentTask, attempt: int) -> bool:
        return task.risk_level == "safe" and attempt < self.max_retries

    @staticmethod
    def recommendation(task: AgentTask) -> str:
        return "retry" if task.risk_level == "safe" else "ask_user"
