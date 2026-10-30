from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from app.productivity.models import CalendarEvent


class CalendarProvider(ABC):
    name: str

    @abstractmethod
    def health(self) -> str: ...

    @abstractmethod
    def list_events(self, start: datetime, end: datetime) -> list[CalendarEvent]: ...

    @abstractmethod
    def create_event(self, event: CalendarEvent) -> CalendarEvent: ...


def conflicts(candidate: CalendarEvent, events: list[CalendarEvent]) -> list[CalendarEvent]:
    return [event for event in events if candidate.start < event.end and event.start < candidate.end]


def free_slots(events: list[CalendarEvent], start: datetime, end: datetime, minimum_minutes: int = 30) -> list[tuple[datetime, datetime]]:
    cursor, result = start, []
    for event in sorted((item for item in events if item.end > start and item.start < end), key=lambda item: item.start):
        event_start = max(start, event.start)
        if event_start - cursor >= timedelta(minutes=minimum_minutes): result.append((cursor, event_start))
        cursor = max(cursor, event.end)
    if end - cursor >= timedelta(minutes=minimum_minutes): result.append((cursor, end))
    return result
