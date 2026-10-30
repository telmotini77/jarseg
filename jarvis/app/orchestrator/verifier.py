from __future__ import annotations

from app.agents.result import AgentResult


class Verifier:
    @staticmethod
    def verify(result: AgentResult) -> bool:
        return result.success and not result.error
