"""Constantes del protocolo MQTT/JSON que comparten JARVIS y los ejemplos."""

from __future__ import annotations

from app.iot.security import normalize_device_id


def esp32_topics(prefix: str, device_id: str) -> dict[str, str]:
    root = f"{prefix.strip().strip('/')}/devices/{normalize_device_id(device_id)}"
    return {purpose: f"{root}/{purpose}" for purpose in ("telemetry", "state", "command", "status", "ack")}


KNOWN_COMMANDS = frozenset({"set_led", "set_relay", "set_servo", "get_state"})
