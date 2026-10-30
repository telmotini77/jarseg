from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, Enum):
    OWNER = "owner"
    STANDARD = "standard"
    GUEST = "guest"


class DataScope(str, Enum):
    PRIVATE = "private"
    SHARED = "shared"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class UserProfile:
    id: str
    display_name: str
    created_at: datetime
    updated_at: datetime
    language: str = "es"
    timezone: str = "America/Guayaquil"
    response_style: str = "technical"
    preferred_voice: str | None = None
    default_project_id: str | None = None
    default_iot_device_id: str | None = None
    role: UserRole = UserRole.STANDARD
    enabled: bool = True
    avatar_url: str | None = None


@dataclass(frozen=True, slots=True)
class UserPreference:
    user_id: str
    key: str
    value: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class UserPermission:
    user_id: str
    capability: str
    allowed: bool
    max_security_level: str = "safe"


@dataclass(frozen=True, slots=True)
class VoiceProfile:
    user_id: str
    tts_voice: str = ""
    speech_rate: float = 1.0
    volume: float = 1.0
    language: str = "es"


@dataclass(frozen=True, slots=True)
class UserContext:
    user_id: str
    display_name: str
    preferences: dict[str, str] = field(default_factory=dict)
    permissions: set[str] = field(default_factory=set)
    default_project: str | None = None
    default_device: str | None = None
    role: UserRole = UserRole.STANDARD

