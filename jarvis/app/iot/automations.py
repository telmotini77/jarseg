"""Reglas persistentes con comparadores explícitos, cooldown y sin eval()."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

from app.iot.events import IoTEventBus
from app.iot.models import IoTEvent, IoTEventType, IoTRule, TelemetryReading, utcnow
from app.iot.repository import IoTRepository
from app.iot.security import SENSORS


OPERATORS = {
    ">": lambda left, right: left > right,
    "<": lambda left, right: left < right,
    ">=": lambda left, right: left >= right,
    "<=": lambda left, right: left <= right,
    "==": lambda left, right: left == right,
}


class RuleEngine:
    def __init__(self, repository: IoTRepository, events: IoTEventBus, cooldown_seconds: int = 60) -> None:
        self.repository = repository
        self.events = events
        self.cooldown_seconds = cooldown_seconds

    def create(self, device_id: str, sensor: str, operator: str, threshold: float, action: str = "notify") -> IoTRule:
        sensor = sensor.casefold().strip()
        if sensor not in SENSORS or operator not in OPERATORS or action not in {"notify", "set_led:on", "set_led:off"}:
            raise ValueError("La regla IoT contiene un sensor, operador o acción no permitidos.")
        if not isinstance(threshold, (int, float)):
            raise ValueError("El umbral debe ser numérico.")
        return self.repository.save_rule(IoTRule(str(uuid4()), device_id, sensor, operator, float(threshold), action))

    def list(self, device_id: str | None = None) -> list[IoTRule]:
        return self.repository.list_rules(device_id)

    def disable(self, device_id: str | None = None, sensor: str | None = None) -> int:
        return self.repository.disable_rules(device_id, sensor.casefold() if sensor else None)

    def evaluate(self, reading: TelemetryReading) -> list[IoTRule]:
        if isinstance(reading.value, bool) or not isinstance(reading.value, (int, float)):
            return []
        triggered: list[IoTRule] = []
        now = utcnow()
        for rule in self.repository.list_rules(reading.device_id, enabled_only=True):
            if rule.sensor != reading.sensor or not OPERATORS[rule.operator](float(reading.value), rule.threshold):
                continue
            if rule.last_triggered_at and now - rule.last_triggered_at < timedelta(seconds=self.cooldown_seconds):
                continue
            updated = self.repository.update_rule(replace(rule, last_triggered_at=now))
            triggered.append(updated)
            self.events.publish(IoTEvent(IoTEventType.IOT_ALERT, reading.device_id, {"rule": updated, "reading": reading}))
        return triggered
