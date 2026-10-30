"""Topics administrados: no se aceptan wildcards ni namespaces arbitrarios por voz."""

from __future__ import annotations

from dataclasses import dataclass

from app.iot.security import normalize_device_id, validate_topic_name


@dataclass(frozen=True, slots=True)
class RoutedTopic:
    device_id: str | None
    purpose: str


class TopicRouter:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix.strip().strip("/")

    @property
    def discovery_topic(self) -> str:
        return f"{self.prefix}/discovery/announce"

    def device_topic(self, device_id: str, purpose: str) -> str:
        identifier = normalize_device_id(device_id)
        if purpose not in {"telemetry", "state", "command", "status", "ack", "heartbeat"}:
            raise ValueError("El propósito MQTT no está permitido.")
        return f"{self.prefix}/devices/{identifier}/{purpose}"

    def route(self, topic: str) -> RoutedTopic | None:
        candidate = topic.strip().strip("/")
        if candidate == self.discovery_topic:
            return RoutedTopic(None, "discovery")
        prefix = f"{self.prefix}/devices/"
        if not candidate.startswith(prefix):
            return None
        parts = candidate[len(prefix):].split("/")
        if len(parts) != 2 or parts[1] not in {"telemetry", "state", "status", "ack", "heartbeat"}:
            return None
        try:
            identifier = normalize_device_id(parts[0])
            validate_topic_name(candidate, self.prefix, identifier)
        except ValueError:
            return None
        return RoutedTopic(identifier, parts[1])
