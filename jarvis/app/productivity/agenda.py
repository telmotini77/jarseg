from __future__ import annotations

from datetime import datetime

from app.productivity.calendar import free_slots
from app.productivity.models import CalendarEvent


def daily_agenda(events: list[CalendarEvent], start: datetime, end: datetime) -> str:
    if not events: return "No tienes eventos en este periodo."
    lines = ["Agenda:", *[f"- {event.start:%H:%M} — {event.title}" for event in sorted(events, key=lambda item: item.start)]]
    slots = free_slots(events, start, end)
    if slots: lines.append("Tiempo libre: " + ", ".join(f"{begin:%H:%M}–{finish:%H:%M}" for begin, finish in slots[:3]))
    return "\n".join(lines)
