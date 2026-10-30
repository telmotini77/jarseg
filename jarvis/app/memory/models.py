from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class MemoryPolicy(str, Enum):
    EXPLICIT_ONLY = "explicit_only"
    SMART = "smart"
    DISABLED = "disabled"


class MemoryType(str, Enum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PREFERENCE = "preference"
    PROJECT = "project"
    TASK = "task"
    SYSTEM = "system"


class MemorySource(str, Enum):
    USER = "user"
    CONVERSATION = "conversation"
    SYSTEM = "system"
    TERMINAL = "terminal"
    BROWSER = "browser"
    PROJECT = "project"
    MODEL = "model"


class MemoryScope(str, Enum):
    PRIVATE = "private"
    SHARED = "shared"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class Memory:
    """Backward-compatible record enriched by Memory Engine 2.0 metadata."""

    id: str
    memory_type: MemoryType | str
    content: str
    created_at: datetime
    updated_at: datetime
    importance: float
    source: MemorySource | str
    key: str | None = None
    confidence: float = 1.0
    project_id: str | None = None
    expires_at: datetime | None = None
    last_accessed_at: datetime | None = None
    embedding_id: str | None = None
    user_id: str | None = None
    scope: MemoryScope | str = MemoryScope.PRIVATE


MemoryRecord = Memory


@dataclass(frozen=True, slots=True)
class MemoryCandidate:
    content: str
    memory_type: MemoryType = MemoryType.SEMANTIC
    importance: float = 0.65
    confidence: float = 0.9
    source: MemorySource = MemorySource.USER
    project_id: str | None = None
    key: str | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Episode:
    id: str
    timestamp: datetime
    title: str
    summary: str
    participants: tuple[str, ...] = ()
    project_id: str | None = None
    importance: float = 0.6


@dataclass(frozen=True, slots=True)
class ProjectMemory:
    id: str
    name: str
    root_path: str
    technologies: tuple[str, ...]
    updated_at: datetime
    metadata: dict[str, object] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True, slots=True)
class MemoryRelationship:
    id: str
    source_memory_id: str
    target_memory_id: str
    relationship_type: str
    confidence: float = 1.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True, slots=True)
class Conversation:
    id: str
    started_at: datetime
    ended_at: datetime | None = None
    summary: str | None = None
    context: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class StoredMessage:
    id: str
    conversation_id: str
    role: str
    content: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class MemoryAuditEntry:
    id: str
    action: str
    memory_id: str | None
    created_at: datetime
    details: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class WorkingMemory:
    active_project: str | None = None
    current_topic: str | None = None
    last_command: str | None = None
    last_error: str | None = None
    last_url: str | None = None
    last_application: str | None = None
    last_conversation: str | None = None
    active_window: str | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc), repr=False)
