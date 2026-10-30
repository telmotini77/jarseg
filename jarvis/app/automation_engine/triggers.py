from __future__ import annotations

from datetime import datetime

from app.automation_engine.models import EventTrigger, TimeTrigger
from app.events.models import JarvisEvent


def event_matches(trigger: EventTrigger, event: JarvisEvent) -> bool:
    return trigger.event_type == event.event_type and all(event.payload.get(key) == value for key, value in trigger.filters.items())


def time_due(trigger: TimeTrigger, now: datetime, last_run_at: datetime | None) -> bool:
    if trigger.frequency != "daily" or not __import__("re").fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", trigger.time):
        return False
    if now.strftime("%H:%M") != trigger.time:
        return False
    return last_run_at is None or last_run_at.date() != now.date()
