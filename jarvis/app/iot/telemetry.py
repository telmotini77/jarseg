"""Almacenamiento acotado y consultas de telemetría; no se manda al Memory Engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.iot.models import TelemetryReading
from app.iot.repository import IoTRepository


class TelemetryManager:
    def __init__(self, repository: IoTRepository, retention_days: int = 30) -> None:
        self.repository = repository
        self.retention_days = retention_days

    def record(self, reading: TelemetryReading) -> TelemetryReading:
        self.repository.save_telemetry(reading)
        self.repository.purge_telemetry_before(datetime.now(timezone.utc) - timedelta(days=self.retention_days))
        return reading

    def latest(self, device_id: str, sensor: str | None = None, limit: int = 5) -> list[TelemetryReading]:
        return self.repository.telemetry(device_id, sensor, limit=limit)

    def maximum_today(self, device_id: str, sensor: str, now: datetime | None = None) -> float | None:
        current = now or datetime.now(timezone.utc)
        start = current.replace(hour=0, minute=0, second=0, microsecond=0)
        return self.repository.maximum(device_id, sensor, start)
