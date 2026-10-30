from __future__ import annotations

from datetime import datetime, timedelta


def cooldown_active(last_run_at: datetime | None, cooldown_seconds: int, now: datetime) -> bool:
    return last_run_at is not None and now - last_run_at < timedelta(seconds=cooldown_seconds)
