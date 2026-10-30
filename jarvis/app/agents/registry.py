from __future__ import annotations

from app.agents.base import Agent, AgentHealth


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        if agent.name in self._agents:
            raise ValueError(f"El agente {agent.name} ya está registrado.")
        self._agents[agent.name] = agent

    def get(self, name: str) -> Agent:
        try:
            return self._agents[name]
        except KeyError as error:
            raise ValueError(f"El agente {name} no está registrado.") from error

    def is_registered_action(self, agent: str, action: str) -> bool:
        try:
            return self.get(agent).supports(action)
        except ValueError:
            return False

    def status(self) -> dict[str, str]:
        return {name: item.health.value for name, item in self._agents.items()}

    def names(self) -> tuple[str, ...]:
        return tuple(self._agents)
