"""Estado actual: cuando se pierde MQTT, las salidas se consideran desconocidas."""

from __future__ import annotations

from dataclasses import replace

from app.iot.models import DeviceState, utcnow
from app.iot.registry import DeviceRegistry
from app.iot.repository import IoTRepository


class StateManager:
    def __init__(self, repository: IoTRepository, devices: DeviceRegistry) -> None:
        self.repository = repository
        self.devices = devices

    def update(self, state: DeviceState) -> DeviceState:
        self.repository.save_state(state)
        self.devices.touch(state.device_id, "online" if state.online else "offline", state.updated_at)
        return state

    def get(self, device_id: str) -> DeviceState | None:
        return self.repository.get_state(device_id)

    def mark_connection_lost(self) -> None:
        for device in self.devices.list():
            previous = self.get(device.id)
            unknown_outputs = {name: "unknown" for name in (previous.outputs if previous else {})}
            self.repository.save_state(DeviceState(device.id, None, unknown_outputs, utcnow(), {"reason": "mqtt_disconnected"}))
            self.devices.touch(device.id, "offline")
