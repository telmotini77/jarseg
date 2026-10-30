from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class TaskStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class Reminder:
    id: str
    title: str
    trigger_at: datetime
    status: TaskStatus
    created_at: datetime
    recurrence: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedSchedule:
    trigger_at: datetime
    recurrence: str | None = None
