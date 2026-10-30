"""Memoria de trabajo efímera: nunca se persiste en la base de datos."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from app.memory.models import WorkingMemory


class WorkingMemoryStore:
    def __init__(self) -> None:
        self._state = WorkingMemory()

    def update(self, **changes: Any) -> WorkingMemory:
        allowed = set(WorkingMemory.__dataclass_fields__) - {"updated_at"}
        for name, value in changes.items():
            if name in allowed and value is not None:
                setattr(self._state, name, value)
        self._state.updated_at = datetime.now(timezone.utc)
        return self._state

    def get(self) -> WorkingMemory:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        data = asdict(self._state)
        data["updated_at"] = self._state.updated_at.isoformat()
        return data
