from __future__ import annotations

from datetime import datetime, timezone

from app.memory.models import Memory


def is_expired(memory: Memory) -> bool:
    return bool(memory.expires_at and memory.expires_at <= datetime.now(timezone.utc))
