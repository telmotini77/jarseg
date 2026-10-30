from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.automation.action import Action


@dataclass(frozen=True, slots=True)
class Routine:
    id: str
    name: str
    actions: list[Action]
    created_at: datetime


@dataclass(slots=True)
class RoutineDraft:
    name: str
    actions: list[Action] = field(default_factory=list)
