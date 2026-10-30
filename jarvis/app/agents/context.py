from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class AgentContext:
    session_id: str
    user_goal: str
    active_project: str | None = None
    memory_context: dict[str, Any] = field(default_factory=dict)
    security_context: dict[str, Any] = field(default_factory=dict)
    shared_state: dict[str, Any] = field(default_factory=dict)
