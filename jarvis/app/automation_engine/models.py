from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class TriggerType(str, Enum):
    TIME = "time"
    EVENT = "event"
    CONDITION = "condition"
    MANUAL = "manual"


class AutomationPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class TimeTrigger:
    time: str
    frequency: str = "daily"
    trigger_type: TriggerType = TriggerType.TIME


@dataclass(frozen=True, slots=True)
class EventTrigger:
    event_type: str
    filters: dict[str, Any] = field(default_factory=dict)
    trigger_type: TriggerType = TriggerType.EVENT


@dataclass(frozen=True, slots=True)
class ConditionTrigger:
    source: str
    trigger_type: TriggerType = TriggerType.CONDITION


@dataclass(frozen=True, slots=True)
class ManualTrigger:
    trigger_type: TriggerType = TriggerType.MANUAL


Trigger = TimeTrigger | EventTrigger | ConditionTrigger | ManualTrigger


@dataclass(frozen=True, slots=True)
class Condition:
    field: str
    operator: str
    value: Any


@dataclass(frozen=True, slots=True)
class AutomationAction:
    agent: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    risk_level: str = "safe"


@dataclass(frozen=True, slots=True)
class Automation:
    name: str
    trigger: Trigger
    conditions: tuple[Condition, ...]
    actions: tuple[AutomationAction, ...]
    enabled: bool = True
    priority: AutomationPriority = AutomationPriority.NORMAL
    policy_snapshot: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_run_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AutomationRun:
    automation_id: str
    success: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
