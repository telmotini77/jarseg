from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from app.tasks.models import ParsedSchedule


_WEEKDAYS = {"lunes": 0, "martes": 1, "miercoles": 2, "jueves": 3, "viernes": 4, "sabado": 5, "domingo": 6}


def _normalized(value: str) -> str:
    decomposed = unicodedata.normalize("NFD", value.casefold())
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")


def _time_from_text(text: str, default_hour: int = 9) -> tuple[int, int]:
    match = re.search(r"a las (\d{1,2})(?::(\d{2}))?\s*(a\.m\.|p\.m\.|am|pm)?", text)
    if match is None:
        return default_hour, 0
    hour, minute, period = int(match.group(1)), int(match.group(2) or 0), (match.group(3) or "").replace(".", "")
    if minute > 59 or hour > 23 or hour < 0:
        raise ValueError("La hora del recordatorio no es válida.")
    if period == "pm" and hour < 12:
        hour += 12
    if period == "am" and hour == 12:
        hour = 0
    return hour, minute


def parse_schedule(expression: str, now: datetime, timezone_name: str) -> ParsedSchedule:
    zone = ZoneInfo(timezone_name)
    local_now = now.astimezone(zone)
    text = _normalized(expression)
    minutes = re.search(r"en (\d+) minutos?", text)
    if minutes:
        return ParsedSchedule(local_now + timedelta(minutes=int(minutes.group(1))))
    if "en una hora" in text:
        return ParsedSchedule(local_now + timedelta(hours=1))

    hour, minute = _time_from_text(text)
    if "manana" in text:
        target = (local_now + timedelta(days=1)).replace(hour=hour, minute=minute, second=0, microsecond=0)
        return ParsedSchedule(target)
    if "hoy" in text:
        target = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return ParsedSchedule(target if target > local_now else target + timedelta(days=1))
    if "cada dia" in text or "todos los dias" in text:
        target = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return ParsedSchedule(target if target > local_now else target + timedelta(days=1), "daily")
    for weekday_name, weekday in _WEEKDAYS.items():
        if f"todos los {weekday_name}" in text or f"cada {weekday_name}" in text:
            delta = (weekday - local_now.weekday()) % 7
            target = (local_now + timedelta(days=delta)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            if target <= local_now:
                target += timedelta(days=7)
            return ParsedSchedule(target, f"weekly:{weekday}")
        if f"el {weekday_name}" in text:
            delta = (weekday - local_now.weekday()) % 7
            target = (local_now + timedelta(days=delta)).replace(hour=hour, minute=minute, second=0, microsecond=0)
            if target <= local_now:
                target += timedelta(days=7)
            return ParsedSchedule(target)
    if "a las" in text:
        target = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return ParsedSchedule(target if target > local_now else target + timedelta(days=1))
    raise ValueError("Indica cuándo debo recordártelo, por ejemplo: en 20 minutos o mañana a las 8.")


def split_reminder_request(text: str) -> tuple[str, str]:
    normalized = _normalized(text)
    starts = [match.start() for match in re.finditer(r"\b(?:en \d+ minutos?|en una hora|manana|hoy|a las|el (?:lunes|martes|miercoles|jueves|viernes|sabado|domingo)|todos los|cada)", normalized)]
    if not starts:
        raise ValueError("Indica cuándo debo recordártelo.")
    index = starts[0]
    title, schedule = text[:index].strip(" ,"), text[index:].strip()
    if not title:
        raise ValueError("Indica qué debo recordarte.")
    return title, schedule
