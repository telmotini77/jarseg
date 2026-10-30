from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.automation_engine.models import Automation, AutomationAction, AutomationPriority, AutomationRun, Condition, ConditionTrigger, EventTrigger, ManualTrigger, TimeTrigger, TriggerType


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _trigger_data(trigger) -> dict[str, Any]:
    if isinstance(trigger, TimeTrigger): return {"type": "time", "time": trigger.time, "frequency": trigger.frequency}
    if isinstance(trigger, EventTrigger): return {"type": "event", "event_type": trigger.event_type, "filters": trigger.filters}
    if isinstance(trigger, ConditionTrigger): return {"type": "condition", "source": trigger.source}
    return {"type": "manual"}


def _trigger(data: dict[str, Any]):
    kind = data.get("type")
    if kind == "time": return TimeTrigger(str(data["time"]), str(data.get("frequency", "daily")))
    if kind == "event": return EventTrigger(str(data["event_type"]), dict(data.get("filters") or {}))
    if kind == "condition": return ConditionTrigger(str(data.get("source", "")))
    return ManualTrigger()


class AutomationRepository:
    def __init__(self, database: str | Path) -> None:
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            self.create_schema(connection)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def create_schema(connection: sqlite3.Connection) -> None:
        connection.execute("""CREATE TABLE IF NOT EXISTS automations (
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, trigger_json TEXT NOT NULL, conditions_json TEXT NOT NULL,
            actions_json TEXT NOT NULL, enabled INTEGER NOT NULL, priority TEXT NOT NULL, policy_json TEXT NOT NULL,
            created_at TEXT NOT NULL, last_run_at TEXT
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_automations_enabled ON automations(enabled)")
        connection.execute("""CREATE TABLE IF NOT EXISTS automation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, automation_id TEXT NOT NULL, started_at TEXT NOT NULL,
            completed_at TEXT, status TEXT NOT NULL, summary TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}'
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_automation_history ON automation_history(automation_id, started_at DESC)")

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Automation:
        conditions = tuple(Condition(item["field"], item["operator"], item.get("value")) for item in json.loads(row["conditions_json"]))
        actions = tuple(AutomationAction(item["agent"], item["action"], dict(item.get("parameters") or {}), item.get("risk_level", "safe")) for item in json.loads(row["actions_json"]))
        return Automation(row["name"], _trigger(json.loads(row["trigger_json"])), conditions, actions, bool(row["enabled"]), AutomationPriority(row["priority"]), json.loads(row["policy_json"]), row["id"], _date(row["created_at"]) or datetime.now(timezone.utc), _date(row["last_run_at"]))

    def save(self, automation: Automation) -> Automation:
        with self._connection() as connection:
            connection.execute("""INSERT INTO automations(id, name, trigger_json, conditions_json, actions_json, enabled, priority, policy_json, created_at, last_run_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, trigger_json=excluded.trigger_json, conditions_json=excluded.conditions_json,
                actions_json=excluded.actions_json, enabled=excluded.enabled, priority=excluded.priority, policy_json=excluded.policy_json, last_run_at=excluded.last_run_at""",
                (automation.id, automation.name, json.dumps(_trigger_data(automation.trigger)), json.dumps([{"field": item.field, "operator": item.operator, "value": item.value} for item in automation.conditions]), json.dumps([{"agent": item.agent, "action": item.action, "parameters": item.parameters, "risk_level": item.risk_level} for item in automation.actions]), int(automation.enabled), automation.priority.value, json.dumps(automation.policy_snapshot), _iso(automation.created_at), _iso(automation.last_run_at)))
        return automation

    def get(self, identifier: str) -> Automation | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM automations WHERE id = ? OR name = ? COLLATE NOCASE", (identifier, identifier)).fetchone()
        return self._from_row(row) if row else None

    def list(self, *, enabled_only: bool = False) -> list[Automation]:
        sql = "SELECT * FROM automations" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY created_at DESC"
        with self._connection() as connection:
            rows = connection.execute(sql).fetchall()
        return [self._from_row(row) for row in rows]

    def set_enabled(self, identifier: str, enabled: bool) -> bool:
        with self._connection() as connection:
            cursor = connection.execute("UPDATE automations SET enabled = ? WHERE id = ? OR name = ? COLLATE NOCASE", (int(enabled), identifier, identifier))
        return cursor.rowcount == 1

    def delete(self, identifier: str) -> bool:
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM automations WHERE id = ? OR name = ? COLLATE NOCASE", (identifier, identifier))
        return cursor.rowcount == 1

    def record_run(self, run: AutomationRun) -> None:
        now = datetime.now(timezone.utc)
        with self._connection() as connection:
            connection.execute("INSERT INTO automation_history(automation_id, started_at, completed_at, status, summary, details_json) VALUES (?, ?, ?, ?, ?, ?)", (run.automation_id, _iso(now), _iso(now), "completed" if run.success else "failed", run.summary, json.dumps(run.data, default=str)))
            connection.execute("UPDATE automations SET last_run_at = ? WHERE id = ?", (_iso(now), run.automation_id))
