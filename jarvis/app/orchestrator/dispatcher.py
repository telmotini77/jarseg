from __future__ import annotations

from app.agents.registry import AgentRegistry


class AgentDispatcher:
    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry

    def resolve(self, agent: str):
        return self.registry.get(agent)
