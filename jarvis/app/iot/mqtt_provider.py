"""Contrato MQTT y proveedor paho-mqtt opcional, aislado del dominio IoT."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass


ConnectedCallback = Callable[[], None]
DisconnectedCallback = Callable[[str], None]
MessageCallback = Callable[[str, bytes], None]


class MQTTProvider(ABC):
    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def disconnect(self) -> None: ...

    @abstractmethod
    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> None: ...

    @abstractmethod
    def subscribe(self, topic: str, qos: int = 0) -> None: ...

    def set_callbacks(
        self, on_connected: ConnectedCallback, on_disconnected: DisconnectedCallback, on_message: MessageCallback
    ) -> None:
        del on_connected, on_disconnected, on_message

    def set_last_will(self, topic: str, payload: str, qos: int = 1, retain: bool = True) -> None:
        del topic, payload, qos, retain


@dataclass(frozen=True, slots=True)
class MQTTProviderConfig:
    host: str
    port: int
    client_id: str
    username: str = ""
    password: str = ""
    use_tls: bool = False
    keepalive: int = 60
    reconnect_max_seconds: int = 30
    reconnect_enabled: bool = True


class PahoMQTTProvider(MQTTProvider):
    """El loop de paho trabaja en segundo plano; nunca se ejecuta shell desde MQTT."""

    def __init__(self, config: MQTTProviderConfig) -> None:
        self.config = config
        self._client = None
        self._on_connected: ConnectedCallback | None = None
        self._on_disconnected: DisconnectedCallback | None = None
        self._on_message: MessageCallback | None = None
        self._last_will: tuple[str, str, int, bool] | None = None

    def set_callbacks(self, on_connected: ConnectedCallback, on_disconnected: DisconnectedCallback, on_message: MessageCallback) -> None:
        self._on_connected, self._on_disconnected, self._on_message = on_connected, on_disconnected, on_message

    def set_last_will(self, topic: str, payload: str, qos: int = 1, retain: bool = True) -> None:
        self._last_will = (topic, payload, qos, retain)

    def connect(self) -> None:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as error:
            raise RuntimeError("Falta paho-mqtt. Instala las dependencias de requirements.txt.") from error
        if self._client is None:
            self._client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=self.config.client_id, protocol=mqtt.MQTTv311)
            if self.config.username:
                self._client.username_pw_set(self.config.username, self.config.password or None)
            if self.config.use_tls:
                self._client.tls_set()
            if self.config.reconnect_enabled:
                self._client.reconnect_delay_set(min_delay=1, max_delay=self.config.reconnect_max_seconds)
            if self._last_will:
                self._client.will_set(*self._last_will)
            self._client.on_connect = self._handle_connect
            self._client.on_disconnect = self._handle_disconnect
            self._client.on_message = self._handle_message
        self._client.connect_async(self.config.host, self.config.port, self.config.keepalive)
        self._client.loop_start()

    def disconnect(self) -> None:
        if self._client is None:
            return
        try:
            self._client.disconnect()
        finally:
            self._client.loop_stop()

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> None:
        if self._client is None:
            raise ConnectionError("MQTT no está conectado.")
        result = self._client.publish(topic, payload, qos=qos, retain=retain)
        if result.rc != 0:
            raise ConnectionError(f"MQTT no pudo publicar el comando (código {result.rc}).")

    def subscribe(self, topic: str, qos: int = 0) -> None:
        if self._client is None:
            raise ConnectionError("MQTT no está conectado.")
        result, _mid = self._client.subscribe(topic, qos=qos)
        if result != 0:
            raise ConnectionError(f"MQTT no pudo suscribirse al topic (código {result}).")

    def _handle_connect(self, _client, _userdata, _flags, result_code, *_extra) -> None:
        if getattr(result_code, "value", result_code) == 0:
            if self._on_connected:
                self._on_connected()
        elif self._on_disconnected:
            self._on_disconnected(f"broker rechazó la conexión ({result_code})")

    def _handle_disconnect(self, _client, _userdata, *_extra) -> None:
        if not self.config.reconnect_enabled and self._client is not None:
            self._client.loop_stop()
        if self._on_disconnected:
            self._on_disconnected("desconectado")

    def _handle_message(self, _client, _userdata, message) -> None:
        if self._on_message:
            self._on_message(str(message.topic), bytes(message.payload))
