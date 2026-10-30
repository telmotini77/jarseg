"""Comandos JSON con request_id, ACK y timeout; no hay publish libre."""

from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

from app.iot.models import IoTCommand, IoTCommandRequest, utcnow
from app.iot.mqtt_client import MQTTClient
from app.iot.repository import IoTRepository
from app.iot.topics import TopicRouter


class CommandManager:
    def __init__(self, repository: IoTRepository, mqtt: MQTTClient, topics: TopicRouter, timeout_seconds: int = 5) -> None:
        self.repository = repository
        self.mqtt = mqtt
        self.topics = topics
        self.timeout_seconds = timeout_seconds

    def send(self, command: IoTCommand) -> IoTCommandRequest:
        request = IoTCommandRequest(str(uuid4()), command.device_id, command.action, utcnow(), details={"parameters": command.parameters})
        payload = json.dumps({"command": command.action, **command.parameters, "request_id": request.request_id}, ensure_ascii=False, separators=(",", ":"))
        self.mqtt.publish(self.topics.device_topic(command.device_id, "command"), payload, qos=1, retain=False)
        self.repository.save_request(request)
        return request

    def acknowledge(self, request_id: str, device_id: str, command: str, success: bool) -> IoTCommandRequest | None:
        original = self.repository.get_request(request_id)
        if original is None or original.device_id != device_id or original.command != command:
            return None
        updated = IoTCommandRequest(
            original.request_id, original.device_id, original.command, original.sent_at, utcnow(),
            "acknowledged" if success else "rejected", {**original.details, "success": success},
        )
        return self.repository.save_request(updated)

    def expire_pending(self) -> list[IoTCommandRequest]:
        before = utcnow() - timedelta(seconds=self.timeout_seconds)
        expired: list[IoTCommandRequest] = []
        for request in self.repository.pending_requests_before(before):
            timed_out = IoTCommandRequest(request.request_id, request.device_id, request.command, request.sent_at, None, "timeout", request.details)
            self.repository.save_request(timed_out)
            expired.append(timed_out)
        return expired
