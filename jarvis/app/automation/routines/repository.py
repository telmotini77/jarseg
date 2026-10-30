from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.automation.action import Action
from app.automation.routines.models import Routine
from app.security.permissions import SecurityLevel


class RoutineRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS routines (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, actions_json TEXT NOT NULL, created_at TEXT NOT NULL
                )"""
            )

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _serialize(actions: list[Action]) -> str:
        return json.dumps([
            {"action_type": item.action_type, "target": item.target, "parameters": item.parameters, "security_level": item.security_level.value}
            for item in actions
        ])

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Routine:
        actions = [
            Action(
                item["action_type"], item.get("target"), dict(item.get("parameters", {})),
                SecurityLevel(item.get("security_level", SecurityLevel.SAFE.value)),
            )
            for item in json.loads(row["actions_json"])
        ]
        return Routine(row["id"], row["name"], actions, datetime.fromisoformat(row["created_at"]))

    def save(self, name: str, actions: list[Action]) -> Routine:
        created_at = datetime.now(timezone.utc)
        existing = self.get(name)
        routine_id = existing.id if existing else str(uuid4())
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO routines(id, name, actions_json, created_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET actions_json = excluded.actions_json",
                (routine_id, name, self._serialize(actions), created_at.isoformat()),
            )
        return self.get(name) or Routine(routine_id, name, actions, created_at)

    def get(self, name: str) -> Routine | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM routines WHERE lower(name) = lower(?)", (name.strip(),)).fetchone()
        return self._from_row(row) if row else None
