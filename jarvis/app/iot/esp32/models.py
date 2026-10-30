from __future__ import annotations

from dataclasses import dataclass

from app.iot.models import IoTDevice


@dataclass(frozen=True, slots=True)
class ESP32Device(IoTDevice):
    board: str | None = None
    firmware_version: str | None = None
    mac_alias: str | None = None
