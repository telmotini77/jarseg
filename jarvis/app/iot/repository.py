"""Persistencia SQLite local para dispositivos, telemetría, reglas y comandos IoT."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.iot.models import DeviceState, IoTCommandRequest, IoTDevice, IoTEvent, IoTRule, MQTTTopic, TelemetryReading, utcnow


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


def _datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class IoTRepository:
    """No comparte objetos de memoria; solo reutiliza la misma base SQLite local."""

    def __init__(self, database: str | Path) -> None:
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            self.create_schema(connection)

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def create_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_devices (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, device_type TEXT NOT NULL, status TEXT NOT NULL,
                last_seen TEXT, capabilities_json TEXT NOT NULL DEFAULT '[]', telemetry_topics_json TEXT NOT NULL DEFAULT '[]',
                command_topics_json TEXT NOT NULL DEFAULT '[]', trusted INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}', state_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_iot_devices_name ON iot_devices(name COLLATE NOCASE)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_topics (
                name TEXT PRIMARY KEY, direction TEXT NOT NULL, device_id TEXT NOT NULL, purpose TEXT NOT NULL,
                qos INTEGER NOT NULL DEFAULT 1, retain INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_topics_device ON iot_topics(device_id)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_telemetry (
                id TEXT PRIMARY KEY, device_id TEXT NOT NULL, sensor TEXT NOT NULL, value_json TEXT NOT NULL,
                unit TEXT, timestamp TEXT NOT NULL,
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_telemetry_query ON iot_telemetry(device_id, sensor, timestamp DESC)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_rules (
                id TEXT PRIMARY KEY, device_id TEXT NOT NULL, sensor TEXT NOT NULL, operator TEXT NOT NULL,
                threshold REAL NOT NULL, action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL, last_triggered_at TEXT,
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_rules_active ON iot_rules(device_id, sensor, enabled)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_command_history (
                request_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, command TEXT NOT NULL, sent_at TEXT NOT NULL,
                acknowledged_at TEXT, status TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_commands_status ON iot_command_history(status, sent_at)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, device_id TEXT,
                details_json TEXT NOT NULL DEFAULT '{}', occurred_at TEXT NOT NULL
            )"""
        )

    @staticmethod
    def _device(row: sqlite3.Row) -> IoTDevice:
        return IoTDevice(
            id=row["id"], name=row["name"], device_type=row["device_type"], status=row["status"],
            last_seen=_datetime(row["last_seen"]), capabilities=tuple(json.loads(row["capabilities_json"])),
            telemetry_topics=tuple(json.loads(row["telemetry_topics_json"])), command_topics=tuple(json.loads(row["command_topics_json"])),
            trusted=bool(row["trusted"]), metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def upsert_device(self, device: IoTDevice) -> IoTDevice:
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO iot_devices(id, name, device_type, status, last_seen, capabilities_json, telemetry_topics_json,
                command_topics_json, trusted, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, device_type=excluded.device_type, status=excluded.status,
                last_seen=excluded.last_seen, capabilities_json=excluded.capabilities_json,
                telemetry_topics_json=excluded.telemetry_topics_json, command_topics_json=excluded.command_topics_json,
                trusted=excluded.trusted, metadata_json=excluded.metadata_json""",
                (device.id, device.name, device.device_type, device.status, _iso(device.last_seen),
                 json.dumps(list(device.capabilities)), json.dumps(list(device.telemetry_topics)),
                 json.dumps(list(device.command_topics)), int(device.trusted), json.dumps(device.metadata)),
            )
        return device

    def get_device(self, device_id: str) -> IoTDevice | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM iot_devices WHERE id = ?", (device_id,)).fetchone()
        return self._device(row) if row else None

    def list_devices(self) -> list[IoTDevice]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM iot_devices ORDER BY name COLLATE NOCASE").fetchall()
        return [self._device(row) for row in rows]

    def update_device_status(self, device_id: str, status: str, last_seen: datetime | None = None) -> IoTDevice | None:
        with self._connection() as connection:
            connection.execute("UPDATE iot_devices SET status = ?, last_seen = COALESCE(?, last_seen) WHERE id = ?", (status, _iso(last_seen), device_id))
        return self.get_device(device_id)

    def set_device_trust(self, device_id: str, trusted: bool) -> IoTDevice | None:
        with self._connection() as connection:
            connection.execute("UPDATE iot_devices SET trusted = ? WHERE id = ?", (int(trusted), device_id))
        return self.get_device(device_id)

    def save_topic(self, topic: MQTTTopic) -> MQTTTopic:
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO iot_topics(name, direction, device_id, purpose, qos, retain) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET direction=excluded.direction, device_id=excluded.device_id,
                purpose=excluded.purpose, qos=excluded.qos, retain=excluded.retain""",
                (topic.name, topic.direction, topic.device_id, topic.purpose, topic.qos, int(topic.retain)),
            )
        return topic

    def topics_for_device(self, device_id: str) -> list[MQTTTopic]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM iot_topics WHERE device_id = ? ORDER BY name", (device_id,)).fetchall()
        return [MQTTTopic(row["name"], row["direction"], row["device_id"], row["purpose"], int(row["qos"]), bool(row["retain"])) for row in rows]

    def save_telemetry(self, reading: TelemetryReading) -> TelemetryReading:
        from uuid import uuid4
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO iot_telemetry(id, device_id, sensor, value_json, unit, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid4()), reading.device_id, reading.sensor, json.dumps(reading.value), reading.unit, _iso(reading.timestamp)),
            )
        return reading

    def telemetry(
        self, device_id: str, sensor: str | None = None, *, limit: int = 5, since: datetime | None = None
    ) -> list[TelemetryReading]:
        clauses, params = ["device_id = ?"], [device_id]
        if sensor:
            clauses.append("sensor = ?")
            params.append(sensor)
        if since:
            clauses.append("timestamp >= ?")
            params.append(_iso(since))
        params.append(max(1, min(limit, 100)))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM iot_telemetry WHERE " + " AND ".join(clauses) + " ORDER BY timestamp DESC LIMIT ?", params
            ).fetchall()
        return [TelemetryReading(row["device_id"], row["sensor"], json.loads(row["value_json"]), row["unit"], _datetime(row["timestamp"]) or utcnow()) for row in rows]

    def maximum(self, device_id: str, sensor: str, since: datetime) -> float | None:
        readings = self.telemetry(device_id, sensor, limit=100, since=since)
        values = [float(item.value) for item in readings if isinstance(item.value, (int, float)) and not isinstance(item.value, bool)]
        return max(values) if values else None

    def purge_telemetry_before(self, before: datetime) -> int:
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM iot_telemetry WHERE timestamp < ?", (_iso(before),))
        return cursor.rowcount

    def save_state(self, state: DeviceState) -> DeviceState:
        data = {"online": state.online, "outputs": state.outputs, "updated_at": _iso(state.updated_at), "details": state.details}
        with self._connection() as connection:
            connection.execute("UPDATE iot_devices SET state_json = ? WHERE id = ?", (json.dumps(data), state.device_id))
        return state

    def get_state(self, device_id: str) -> DeviceState | None:
        with self._connection() as connection:
            row = connection.execute("SELECT state_json FROM iot_devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            return None
        data = json.loads(row["state_json"] or "{}")
        if not data:
            return None
        return DeviceState(device_id, data.get("online"), dict(data.get("outputs") or {}), _datetime(data.get("updated_at")) or utcnow(), dict(data.get("details") or {}))

    def save_rule(self, rule: IoTRule) -> IoTRule:
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO iot_rules(id, device_id, sensor, operator, threshold, action, enabled, created_at, last_triggered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET device_id=excluded.device_id, sensor=excluded.sensor, operator=excluded.operator,
                threshold=excluded.threshold, action=excluded.action, enabled=excluded.enabled, last_triggered_at=excluded.last_triggered_at""",
                (rule.id, rule.device_id, rule.sensor, rule.operator, rule.threshold, rule.action, int(rule.enabled), _iso(rule.created_at), _iso(rule.last_triggered_at)),
            )
        return rule

    @staticmethod
    def _rule(row: sqlite3.Row) -> IoTRule:
        return IoTRule(row["id"], row["device_id"], row["sensor"], row["operator"], float(row["threshold"]), row["action"], bool(row["enabled"]), _datetime(row["created_at"]) or utcnow(), _datetime(row["last_triggered_at"]))

    def list_rules(self, device_id: str | None = None, *, enabled_only: bool = False) -> list[IoTRule]:
        clauses, params = [], []
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        if enabled_only:
            clauses.append("enabled = 1")
        sql = "SELECT * FROM iot_rules" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY created_at DESC"
        with self._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._rule(row) for row in rows]

    def update_rule(self, rule: IoTRule) -> IoTRule:
        return self.save_rule(rule)

    def disable_rules(self, device_id: str | None = None, sensor: str | None = None) -> int:
        clauses, params = ["enabled = 1"], []
        if device_id:
            clauses.append("device_id = ?")
            params.append(device_id)
        if sensor:
            clauses.append("sensor = ?")
            params.append(sensor)
        with self._connection() as connection:
            cursor = connection.execute("UPDATE iot_rules SET enabled = 0 WHERE " + " AND ".join(clauses), params)
        return cursor.rowcount

    def save_request(self, request: IoTCommandRequest) -> IoTCommandRequest:
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO iot_command_history(request_id, device_id, command, sent_at, acknowledged_at, status, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET acknowledged_at=excluded.acknowledged_at,
                status=excluded.status, details_json=excluded.details_json""",
                (request.request_id, request.device_id, request.command, _iso(request.sent_at), _iso(request.acknowledged_at), request.status, json.dumps(request.details)),
            )
        return request

    def get_request(self, request_id: str) -> IoTCommandRequest | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM iot_command_history WHERE request_id = ?", (request_id,)).fetchone()
        return self._request(row) if row else None

    @staticmethod
    def _request(row: sqlite3.Row) -> IoTCommandRequest:
        return IoTCommandRequest(row["request_id"], row["device_id"], row["command"], _datetime(row["sent_at"]) or utcnow(), _datetime(row["acknowledged_at"]), row["status"], json.loads(row["details_json"] or "{}"))

    def pending_requests_before(self, before: datetime) -> list[IoTCommandRequest]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM iot_command_history WHERE status = 'pending' AND sent_at < ?", (_iso(before),)).fetchall()
        return [self._request(row) for row in rows]

    def log_event(self, event: IoTEvent) -> None:
        with self._connection() as connection:
            connection.execute("INSERT INTO iot_events(event_type, device_id, details_json, occurred_at) VALUES (?, ?, ?, ?)", (event.event_type.value, event.device_id, json.dumps(event.details, default=str), _iso(event.occurred_at)))
