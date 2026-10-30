"""Validación defensiva: MQTT nunca ejecuta texto arbitrario ni comandos libres."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.iot.models import IoTCommand, IoTDevice


SENSORS = frozenset({
    "temperature", "humidity", "light", "ldr", "distance", "motion", "infrared",
    "button", "digital_input", "analog_input",
})
ACTUATORS = frozenset({"led", "relay", "buzzer", "servo", "digital_output"})
SAFE_ACTIONS = frozenset({"get_state"})
ACTION_CAPABILITIES = {
    "set_led": "led",
    "set_relay": "relay",
    "set_buzzer": "buzzer",
    "set_servo": "servo",
    "set_digital_output": "digital_output",
    "get_state": None,
}
CONFIRMATION_ACTIONS = frozenset({"set_relay", "set_buzzer", "set_servo", "set_digital_output"})
_DEVICE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def normalize_device_id(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    if not _DEVICE_ID.fullmatch(normalized):
        raise ValueError("El identificador IoT debe usar letras, números y guiones, sin comodines ni rutas.")
    return normalized


def validate_topic_name(topic: str, prefix: str, device_id: str | None = None) -> str:
    candidate = topic.strip().strip("/")
    root = prefix.strip().strip("/")
    if not candidate or "#" in candidate or "+" in candidate or ".." in candidate or "//" in candidate:
        raise ValueError("El topic MQTT contiene un comodín o una ruta no permitida.")
    if not candidate.startswith(root + "/"):
        raise ValueError("El topic MQTT está fuera del namespace configurado.")
    if device_id and f"/devices/{normalize_device_id(device_id)}/" not in f"/{candidate}/":
        raise ValueError("El topic MQTT no pertenece al dispositivo solicitado.")
    return candidate


def redact_broker(host: str) -> str:
    """El host no es secreto; evita imprimir accidentalmente URL con credenciales."""
    return re.sub(r"//[^/@]+@", "//***@", host)


@dataclass(frozen=True, slots=True)
class CommandValidation:
    command: IoTCommand | None
    message: str | None = None


class IoTCommandValidator:
    """Resuelve exclusivamente acciones registradas contra un dispositivo confiable."""

    def validate(self, device: IoTDevice, action: str, parameters: dict[str, Any] | None = None) -> CommandValidation:
        if not device.trusted:
            return CommandValidation(None, f"El dispositivo {device.name} aún no es confiable; no enviaré comandos.")
        if device.status != "online":
            return CommandValidation(None, f"El dispositivo {device.name} está offline; no enviaré el comando.")
        if action not in ACTION_CAPABILITIES:
            return CommandValidation(None, "La acción IoT solicitada no está registrada.")
        required = ACTION_CAPABILITIES[action]
        if required and required not in device.capabilities:
            return CommandValidation(None, f"{device.name} no tiene la capacidad {required} registrada.")
        values = dict(parameters or {})
        if action in {"set_led", "set_relay", "set_buzzer", "set_digital_output"}:
            value = values.get("value")
            if not isinstance(value, bool):
                return CommandValidation(None, "La salida digital solo admite true o false.")
        if action == "set_servo":
            value = values.get("angle", values.get("value"))
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 180:
                return CommandValidation(None, "El servo solo admite valores entre 0 y 180 grados.")
            values = {"angle": int(value)}
        return CommandValidation(
            IoTCommand(
                device_id=device.id,
                action=action,
                parameters=values,
                risk_level="confirmation" if action in CONFIRMATION_ACTIONS else "safe",
                requires_confirmation=action in CONFIRMATION_ACTIONS,
            )
        )
