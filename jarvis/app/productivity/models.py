from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class ProviderHealth(str, Enum):
    CONNECTED = "connected"
    AUTH_REQUIRED = "auth_required"
    DISCONNECTED = "disconnected"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class CalendarEvent:
    id: str
    title: str
    start: datetime
    end: datetime
    location: str | None = None
    description: str | None = None
    attendees: tuple[str, ...] = ()
    calendar_id: str = "primary"
    provider: str = "google"


@dataclass(frozen=True, slots=True)
class EmailMessage:
    id: str
    thread_id: str
    sender: str
    recipients: tuple[str, ...]
    subject: str
    snippet: str
    received_at: datetime
    labels: tuple[str, ...] = ()
    has_attachments: bool = False
    unread: bool = False
    provider: str = "gmail"


@dataclass(frozen=True, slots=True)
class EmailDraft:
    id: str
    recipient: str
    subject: str
    body: str
    reply_to_message_id: str | None = None


@dataclass(frozen=True, slots=True)
class PriorityItem:
    id: str
    title: str
    source: str
    priority: str
    due_at: datetime | None
    reason: str


@dataclass(frozen=True, slots=True)
class ProductivityContext:
    next_event: CalendarEvent | None
    important_email_count: int
    unread_count: int
    reminders_today: int
    free_slots: tuple[tuple[datetime, datetime], ...] = ()
