"""Descubrimiento controlado: un anuncio MQTT no concede confianza."""

from __future__ import annotations

from app.iot.events import IoTEventBus
from app.iot.models import IoTDevice, IoTEvent, IoTEventType
from app.iot.registry import DeviceRegistry


class DiscoveryManager:
    def __init__(self, devices: DeviceRegistry, events: IoTEventBus) -> None:
        self.devices = devices
        self.events = events

    def announce(self, device_id: str, device_type: str, capabilities: tuple[str, ...]) -> tuple[IoTDevice, bool]:
        existing = self.devices.get(device_id)
        if existing is not None:
            return existing, False
        device = self.devices.register(device_id, device_id=device_id, device_type=device_type, capabilities=capabilities, trusted=False)
        self.events.publish(IoTEvent(IoTEventType.DEVICE_DISCOVERED, device.id, {"name": device.name, "capabilities": list(device.capabilities)}))
        return device, True
