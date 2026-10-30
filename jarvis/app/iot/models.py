"""Modelos de dominio explícitos para el agente IoT."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MQTTConnectionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"


class IoTEventType(str, Enum):
    IOT_CONNECTED = "IOT_CONNECTED"
    IOT_DISCONNECTED = "IOT_DISCONNECTED"
    DEVICE_ONLINE = "DEVICE_ONLINE"
    DEVICE_OFFLINE = "DEVICE_OFFLINE"
    TELEMETRY_RECEIVED = "TELEMETRY_RECEIVED"
    STATE_CHANGED = "STATE_CHANGED"
    COMMAND_SENT = "COMMAND_SENT"
    COMMAND_ACKNOWLEDGED = "COMMAND_ACKNOWLEDGED"
    IOT_ALERT = "IOT_ALERT"
    DEVICE_DISCOVERED = "DEVICE_DISCOVERED"


@dataclass(frozen=True, slots=True)
class IoTDevice:
    id: str
    name: str
    device_type: str
    status: str = "offline"
    last_seen: datetime | None = None
    capabilities: tuple[str, ...] = ()
    telemetry_topics: tuple[str, ...] = ()
    command_topics: tuple[str, ...] = ()
    trusted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MQTTTopic:
    name: str
    direction: str
    device_id: str
    purpose: str
    qos: int = 1
    retain: bool = False


@dataclass(frozen=True, slots=True)
class TelemetryReading:
    device_id: str
    sensor: str
    value: float | str | bool
    unit: str | None
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class IoTCommand:
    device_id: str
    action: str
    parameters: dict[str, Any]
    risk_level: str
    requires_confirmation: bool


@dataclass(frozen=True, slots=True)
class IoTCommandRequest:
    request_id: str
    device_id: str
    command: str
    sent_at: datetime
    acknowledged_at: datetime | None = None
    status: str = "pending"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DeviceState:
    device_id: str
    online: bool | None
    outputs: dict[str, bool | str | float]
    updated_at: datetime
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IoTRule:
    id: str
    device_id: str
    sensor: str
    operator: str
    threshold: float
    action: str
    enabled: bool = True
    created_at: datetime = field(default_factory=utcnow)
    last_triggered_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IoTEvent:
    event_type: IoTEventType
    device_id: str | None
    details: dict[str, Any]
    occurred_at: datetime = field(default_factory=utcnow)
