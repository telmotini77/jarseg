"""Operaciones de alto nivel del registro y estado de dispositivos."""

from __future__ import annotations

from app.iot.models import IoTDevice
from app.iot.registry import DeviceRegistry
from app.iot.state import StateManager


class DeviceManager:
    def __init__(self, registry: DeviceRegistry, states: StateManager, default_device: str | None = None) -> None:
        self.registry = registry
        self.states = states
        self.default_device = default_device or None

    def resolve(self, reference: str | None = None) -> IoTDevice:
        return self.registry.resolve(reference, self.default_device)

    def list(self) -> list[IoTDevice]:
        return self.registry.list()

    def health(self, reference: str | None = None) -> tuple[IoTDevice, object | None]:
        device = self.resolve(reference)
        return device, self.states.get(device.id)
