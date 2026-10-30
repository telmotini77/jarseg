from __future__ import annotations

from dataclasses import dataclass, field

from app.security.permissions import SecurityLevel


@dataclass(frozen=True, slots=True)
class Action:
    action_type: str
    target: str | None = None
    parameters: dict[str, object] = field(default_factory=dict)
    security_level: SecurityLevel = SecurityLevel.SAFE
