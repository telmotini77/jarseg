from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AgentResult:
    task_id: str
    agent: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    error: str | None = None
