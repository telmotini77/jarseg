from __future__ import annotations

from app.events.models import JarvisEvent


def event_summary(event: JarvisEvent) -> str:
    return f"{event.event_type} desde {event.source}"
