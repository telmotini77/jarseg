"""Validación de payloads MQTT entrantes, sin ejecutar su contenido."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.iot.models import DeviceState, IoTCommandRequest, TelemetryReading, utcnow
from app.iot.security import SENSORS, normalize_device_id


def parse_json_payload(payload: bytes | str, max_bytes: int) -> dict[str, Any]:
    raw = payload.encode("utf-8") if isinstance(payload, str) else payload
    if len(raw) > max_bytes:
        raise ValueError("El payload MQTT supera el tamaño máximo permitido.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("El payload MQTT no contiene JSON válido.") from error
    if not isinstance(value, dict):
        raise ValueError("El payload MQTT debe ser un objeto JSON.")
    return value


def validate_device_identity(payload: dict[str, Any], topic_device_id: str) -> str:
    claimed = payload.get("device_id")
    if not isinstance(claimed, str) or normalize_device_id(claimed) != normalize_device_id(topic_device_id):
        raise ValueError("El device_id del payload no coincide con el topic MQTT.")
    return normalize_device_id(claimed)


def _timestamp(value: object) -> datetime:
    if value is None:
        return utcnow()
    if isinstance(value, bool):
        raise ValueError("El timestamp MQTT no es válido.")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise ValueError("El timestamp MQTT no es válido.")


def parse_telemetry(payload: dict[str, Any], topic_device_id: str) -> list[TelemetryReading]:
    device_id = validate_device_identity(payload, topic_device_id)
    sensors = payload.get("sensors")
    if not isinstance(sensors, dict) or not sensors:
        raise ValueError("La telemetría debe incluir un objeto sensors no vacío.")
    timestamp = _timestamp(payload.get("timestamp"))
    units = payload.get("units", {})
    if not isinstance(units, dict):
        raise ValueError("units debe ser un objeto JSON cuando se incluye.")
    readings: list[TelemetryReading] = []
    for sensor, value in sensors.items():
        if not isinstance(sensor, str) or not sensor.casefold() in SENSORS:
            raise ValueError("La telemetría contiene un sensor no permitido.")
        if isinstance(value, (dict, list)) or value is None:
            raise ValueError("El valor de telemetría debe ser escalar.")
        if not isinstance(value, (float, int, str, bool)):
            raise ValueError("El valor de telemetría no tiene un tipo permitido.")
        unit = units.get(sensor)
        if unit is not None and not isinstance(unit, str):
            raise ValueError("La unidad de telemetría debe ser texto.")
        readings.append(TelemetryReading(device_id, sensor.casefold(), value, unit, timestamp))
    return readings


def parse_state(payload: dict[str, Any], topic_device_id: str) -> DeviceState:
    device_id = validate_device_identity(payload, topic_device_id)
    online = payload.get("online")
    if not isinstance(online, bool):
        raise ValueError("El estado MQTT debe incluir online como booleano.")
    outputs = payload.get("outputs", {})
    if not isinstance(outputs, dict) or any(not isinstance(key, str) or isinstance(value, (dict, list)) for key, value in outputs.items()):
        raise ValueError("outputs debe contener valores escalares.")
    return DeviceState(device_id, online, dict(outputs), _timestamp(payload.get("timestamp")), {key: value for key, value in payload.items() if key not in {"device_id", "online", "outputs", "timestamp"}})


def parse_ack(payload: dict[str, Any], topic_device_id: str) -> IoTCommandRequest:
    device_id = validate_device_identity(payload, topic_device_id)
    request_id, command, success = payload.get("request_id"), payload.get("command"), payload.get("success")
    if not isinstance(request_id, str) or not request_id or not isinstance(command, str) or not isinstance(success, bool):
        raise ValueError("El ACK MQTT no contiene request_id, command y success válidos.")
    return IoTCommandRequest(request_id, device_id, command, utcnow(), utcnow(), "acknowledged" if success else "rejected", {"success": success})


def parse_discovery(payload: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    device_id = payload.get("device_id")
    device_type = payload.get("device_type", "esp32")
    capabilities = payload.get("capabilities", [])
    if not isinstance(device_id, str) or not isinstance(device_type, str) or not isinstance(capabilities, list) or not all(isinstance(item, str) for item in capabilities):
        raise ValueError("El anuncio de descubrimiento no es válido.")
    return normalize_device_id(device_id), device_type.casefold(), tuple(item.casefold() for item in capabilities)
