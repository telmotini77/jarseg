from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

from app.agents.context import AgentContext
from app.agents.result import AgentResult


class AgentHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class AgentTask:
    agent: str
    action: str
    objective: str
    parameters: dict[str, Any] = field(default_factory=dict)
    dependencies: tuple[str, ...] = ()
    risk_level: str = "safe"
    resources: tuple[str, ...] = ()
    id: str = field(default_factory=lambda: str(uuid4()))


class Agent(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def capabilities(self) -> set[str]: ...

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY

    def supports(self, action: str) -> bool:
        return action in self.capabilities

    @abstractmethod
    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult: ...
