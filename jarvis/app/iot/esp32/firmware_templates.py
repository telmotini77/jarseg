"""Ubicaciones de las plantillas compilables de ejemplo, sin credenciales reales."""

from __future__ import annotations

from pathlib import Path


def examples_root() -> Path:
    return Path(__file__).resolve().parents[3] / "examples" / "esp32"


def available_templates() -> dict[str, Path]:
    root = examples_root()
    return {
        "basic_mqtt_device": root / "basic_mqtt_device" / "basic_mqtt_device.ino",
        "dht11_mqtt": root / "dht11_mqtt" / "dht11_mqtt.ino",
        "ldr_led_mqtt": root / "ldr_led_mqtt" / "ldr_led_mqtt.ino",
    }
