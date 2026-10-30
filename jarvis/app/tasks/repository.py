from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.tasks.models import Reminder, TaskStatus


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


class TaskRepository:
    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS reminders (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    trigger_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    recurrence TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_reminders_pending ON reminders(status, trigger_at);
                """
            )

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Reminder:
        return Reminder(
            id=row["id"], title=row["title"], trigger_at=_parse(row["trigger_at"]),
            status=TaskStatus(row["status"]), created_at=_parse(row["created_at"]), recurrence=row["recurrence"],
        )

    def create(self, title: str, trigger_at: datetime, recurrence: str | None = None) -> Reminder:
        reminder = Reminder(str(uuid4()), title.strip(), trigger_at, TaskStatus.PENDING, _now(), recurrence)
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO reminders VALUES (?, ?, ?, ?, ?, ?)",
                (reminder.id, reminder.title, reminder.trigger_at.isoformat(), reminder.status.value, reminder.created_at.isoformat(), reminder.recurrence),
            )
        return reminder

    def list_pending(self) -> list[Reminder]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM reminders WHERE status = ? ORDER BY trigger_at", (TaskStatus.PENDING.value,)).fetchall()
        return [self._from_row(row) for row in rows]

    def list_due(self, now: datetime) -> list[Reminder]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM reminders WHERE status = ? AND trigger_at <= ? ORDER BY trigger_at",
                (TaskStatus.PENDING.value, now.isoformat()),
            ).fetchall()
        return [self._from_row(row) for row in rows]

    def update_status(self, reminder_id: str, status: TaskStatus) -> bool:
        with self._connection() as connection:
            return connection.execute("UPDATE reminders SET status = ? WHERE id = ?", (status.value, reminder_id)).rowcount == 1

    def reschedule(self, reminder_id: str, trigger_at: datetime) -> bool:
        with self._connection() as connection:
            return connection.execute(
                "UPDATE reminders SET trigger_at = ?, status = ? WHERE id = ?",
                (trigger_at.isoformat(), TaskStatus.PENDING.value, reminder_id),
            ).rowcount == 1

    def find_pending(self, query: str) -> list[Reminder]:
        cleaned = query.casefold().strip()
        return [item for item in self.list_pending() if cleaned in item.title.casefold()]
