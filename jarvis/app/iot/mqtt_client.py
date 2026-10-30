"""Cliente MQTT con estado y suscripciones administradas."""

from __future__ import annotations

import logging
from collections.abc import Callable

from app.iot.models import MQTTConnectionState
from app.iot.mqtt_provider import MQTTProvider


class MQTTClient:
    def __init__(self, provider: MQTTProvider, logger: logging.Logger | None = None, *, reconnect_enabled: bool = True) -> None:
        self.provider = provider
        self.logger = logger or logging.getLogger("jarvis.iot.mqtt")
        self.state = MQTTConnectionState.DISCONNECTED
        self.reconnect_enabled = reconnect_enabled
        self._manual_disconnect = False
        self._subscriptions: dict[str, int] = {}
        self._message_handler: Callable[[str, bytes], None] | None = None
        self._state_handler: Callable[[MQTTConnectionState, str | None], None] | None = None
        provider.set_callbacks(self._connected, self._disconnected, self._message)

    @property
    def subscriptions(self) -> tuple[str, ...]:
        return tuple(self._subscriptions)

    def set_handlers(
        self, message_handler: Callable[[str, bytes], None], state_handler: Callable[[MQTTConnectionState, str | None], None]
    ) -> None:
        self._message_handler, self._state_handler = message_handler, state_handler

    def connect(self) -> None:
        if self.state in {MQTTConnectionState.CONNECTED, MQTTConnectionState.CONNECTING}:
            return
        self._change_state(MQTTConnectionState.CONNECTING)
        try:
            self.provider.connect()
        except Exception:
            self._change_state(MQTTConnectionState.DISCONNECTED)
            raise

    def disconnect(self) -> None:
        self._manual_disconnect = True
        try:
            self.provider.disconnect()
        finally:
            self._change_state(MQTTConnectionState.DISCONNECTED)
            self._manual_disconnect = False

    def publish(self, topic: str, payload: str, *, qos: int = 1, retain: bool = False) -> None:
        if self.state is not MQTTConnectionState.CONNECTED:
            raise ConnectionError("MQTT no está conectado; no enviaré el comando.")
        self.provider.publish(topic, payload, qos=qos, retain=retain)

    def subscribe(self, topic: str, *, qos: int = 1) -> None:
        if self.state is not MQTTConnectionState.CONNECTED:
            raise ConnectionError("MQTT no está conectado; no puedo suscribirme.")
        self.provider.subscribe(topic, qos=qos)
        self._subscriptions[topic] = qos

    def _connected(self) -> None:
        self._change_state(MQTTConnectionState.CONNECTED)
        for topic, qos in tuple(self._subscriptions.items()):
            try:
                self.provider.subscribe(topic, qos=qos)
            except Exception as error:
                self.logger.warning("IOT resubscribe failed reason=%s", type(error).__name__)

    def _disconnected(self, reason: str) -> None:
        target = MQTTConnectionState.DISCONNECTED if self._manual_disconnect or not self.reconnect_enabled else MQTTConnectionState.RECONNECTING
        self._change_state(target, reason)

    def _message(self, topic: str, payload: bytes) -> None:
        if self._message_handler:
            self._message_handler(topic, payload)

    def _change_state(self, state: MQTTConnectionState, reason: str | None = None) -> None:
        self.state = state
        if self._state_handler:
            self._state_handler(state, reason)
