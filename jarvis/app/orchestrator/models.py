from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from app.agents.base import AgentTask
from app.agents.result import AgentResult


class OrchestratorMode(str, Enum):
    READ_ONLY = "read_only"
    ASSIST = "assist"
    AUTONOMOUS_SAFE = "autonomous_safe"


class OrchestratorStatus(str, Enum):
    IDLE = "idle"
    PLANNING = "planning"
    WAITING_CONFIRMATION = "waiting_confirmation"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class UserGoal:
    text: str
    user_id: str | None = None
    source: str = "user"
    mode: str = OrchestratorMode.ASSIST.value
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    goal_id: str
    tasks: tuple[AgentTask, ...]
    status: str = "planned"
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True, slots=True)
class OrchestrationResult:
    plan_id: str
    success: bool
    summary: str
    task_results: dict[str, AgentResult] = field(default_factory=dict)
    error: str | None = None
