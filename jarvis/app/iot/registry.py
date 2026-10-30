"""Registro explícito de dispositivos y acciones IoT permitidas."""

from __future__ import annotations

from dataclasses import replace

from app.iot.models import IoTDevice, MQTTTopic
from app.iot.repository import IoTRepository
from app.iot.security import ACTION_CAPABILITIES, normalize_device_id, validate_topic_name


IOT_ACTION_REGISTRY = frozenset({
    "iot_connect", "iot_disconnect", "iot_list_devices", "iot_get_state", "iot_get_telemetry",
    "iot_set_led", "iot_set_relay", "iot_set_servo", "iot_set_buzzer", "iot_subscribe",
    "iot_create_rule", "iot_register_device", "iot_list_rules", "iot_disable_rule",
    "iot_disable_all_rules", "iot_check_tools",
})


class DeviceRegistry:
    def __init__(self, repository: IoTRepository, topic_prefix: str) -> None:
        self.repository = repository
        self.topic_prefix = topic_prefix.strip().strip("/")

    def register(
        self, name: str, *, device_id: str | None = None, device_type: str = "esp32",
        capabilities: tuple[str, ...] | list[str] = (), trusted: bool = False,
    ) -> IoTDevice:
        identifier = normalize_device_id(device_id or name)
        normalized_capabilities = tuple(dict.fromkeys(str(capability).casefold().strip() for capability in capabilities if str(capability).strip()))
        telemetry = tuple(self.topic(identifier, purpose) for purpose in ("telemetry", "state", "status"))
        commands = (self.topic(identifier, "command"),)
        existing = self.repository.get_device(identifier)
        device = IoTDevice(
            id=identifier, name=name.strip() or identifier, device_type=device_type.casefold().strip() or "esp32",
            status=existing.status if existing else "offline", last_seen=existing.last_seen if existing else None,
            capabilities=normalized_capabilities or (existing.capabilities if existing else ()),
            telemetry_topics=telemetry, command_topics=commands,
            trusted=trusted if existing is None else (trusted or existing.trusted), metadata=existing.metadata if existing else {},
        )
        self.repository.upsert_device(device)
        for purpose, direction, retain in (("telemetry", "in", False), ("state", "in", True), ("status", "in", True), ("ack", "in", False), ("command", "out", False)):
            self.repository.save_topic(MQTTTopic(self.topic(identifier, purpose), direction, identifier, purpose, 1, retain))
        return device

    def topic(self, device_id: str, purpose: str) -> str:
        identifier = normalize_device_id(device_id)
        if purpose not in {"telemetry", "state", "command", "status", "ack", "heartbeat"}:
            raise ValueError("El propósito del topic IoT no está registrado.")
        return f"{self.topic_prefix}/devices/{identifier}/{purpose}"

    def get(self, device_id: str) -> IoTDevice | None:
        return self.repository.get_device(normalize_device_id(device_id))

    def list(self) -> list[IoTDevice]:
        return self.repository.list_devices()

    def resolve(self, reference: str | None, default_device: str | None = None) -> IoTDevice:
        if reference:
            needle = reference.casefold().strip()
            candidates = [item for item in self.list() if needle in {item.id.casefold(), item.name.casefold()} or needle in item.id.casefold() or needle in item.name.casefold()]
        elif default_device:
            candidates = [item for item in self.list() if item.id == default_device]
        else:
            candidates = self.list()
        if not candidates:
            raise ValueError("No hay un dispositivo IoT registrado que coincida. Registra primero el ESP32.")
        if len(candidates) > 1:
            names = ", ".join(item.name for item in candidates[:4])
            raise ValueError(f"Hay varios dispositivos posibles: {names}. Indica cuál.")
        return candidates[0]

    def touch(self, device_id: str, status: str | None = None, when=None) -> IoTDevice | None:
        device = self.get(device_id)
        if device is None:
            return None
        return self.repository.update_device_status(device.id, status or device.status, when)

    def trust(self, device_id: str, trusted: bool = True) -> IoTDevice | None:
        return self.repository.set_device_trust(normalize_device_id(device_id), trusted)

    def validate_topic(self, topic: str, device_id: str) -> str:
        return validate_topic_name(topic, self.topic_prefix, device_id)

    def has_action(self, action: str) -> bool:
        return action in ACTION_CAPABILITIES
