from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from app.commands.base import Command, CommandResult
from app.commands.router import CommandRouter
from app.code.language_detector import detect_language
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis
from app.iot.agent import IoTAgent
from app.iot.models import IoTCommandRequest, MQTTConnectionState, TelemetryReading, utcnow
from app.iot.mqtt_provider import MQTTProvider
from app.iot.repository import IoTRepository
from app.iot.security import validate_topic_name
from app.memory.manager import MemoryManager
from app.memory.repository import MemoryRepository
from app.security.permissions import PermissionManager, SecurityLevel


@dataclass
class FakeMQTTProvider(MQTTProvider):
    published: list[tuple[str, str, int, bool]] = field(default_factory=list)
    subscriptions: list[tuple[str, int]] = field(default_factory=list)
    connected: bool = False
    on_connected: object | None = None
    on_disconnected: object | None = None
    on_message: object | None = None

    def set_callbacks(self, on_connected, on_disconnected, on_message) -> None:
        self.on_connected, self.on_disconnected, self.on_message = on_connected, on_disconnected, on_message

    def connect(self) -> None:
        self.connected = True
        assert callable(self.on_connected)
        self.on_connected()

    def disconnect(self) -> None:
        self.connected = False
        assert callable(self.on_disconnected)
        self.on_disconnected("manual")

    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> None:
        if not self.connected:
            raise ConnectionError("offline")
        self.published.append((topic, payload, qos, retain))

    def subscribe(self, topic: str, qos: int = 0) -> None:
        if not self.connected:
            raise ConnectionError("offline")
        self.subscriptions.append((topic, qos))

    def emit(self, topic: str, payload: dict | str) -> None:
        assert callable(self.on_message)
        data = json.dumps(payload).encode("utf-8") if isinstance(payload, dict) else payload.encode("utf-8")
        self.on_message(topic, data)


def make_agent(tmp_path: Path) -> tuple[IoTAgent, FakeMQTTProvider]:
    provider = FakeMQTTProvider()
    return IoTAgent(provider, IoTRepository(tmp_path / "jarvis.db"), topic_prefix="jarvis/test", rule_cooldown_seconds=300), provider


def online_device(agent: IoTAgent, provider: FakeMQTTProvider, *, capabilities: tuple[str, ...] = ("temperature", "humidity", "ldr", "led", "servo")) -> None:
    agent.register_esp32("laboratorio", capabilities)
    agent.connect()
    provider.emit(agent.topics.device_topic("laboratorio", "status"), "online")


def test_mqtt_connects_in_background_and_uses_only_registered_topics(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    agent.register_esp32("laboratorio", ("temperature",))
    assert "conectado" in agent.connect().casefold()
    assert agent.connection_state is MQTTConnectionState.CONNECTED
    subscribed = {topic for topic, _ in provider.subscriptions}
    assert agent.topics.discovery_topic in subscribed
    assert agent.topics.device_topic("laboratorio", "telemetry") in subscribed
    assert callable(provider.on_disconnected) and callable(provider.on_connected)
    provider.on_disconnected("network")
    assert agent.connection_state is MQTTConnectionState.RECONNECTING
    provider.on_connected()
    assert agent.connection_state is MQTTConnectionState.CONNECTED
    with pytest.raises(ValueError):
        validate_topic_name("jarvis/test/devices/laboratorio/#", "jarvis/test", "laboratorio")
    with pytest.raises(ValueError):
        validate_topic_name("jarvis/other/devices/laboratorio/state", "jarvis/test", "laboratorio")


def test_telemetry_is_validated_persisted_and_device_spoofing_is_rejected(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    online_device(agent, provider)
    topic = agent.topics.device_topic("laboratorio", "telemetry")
    provider.emit(topic, {"device_id": "laboratorio", "sensors": {"temperature": 24.7, "humidity": 61.2}})
    response = agent.get_telemetry("temperature", "laboratorio")
    assert "24.7" in response and "temperatura" in response
    provider.emit(topic, {"device_id": "otro-esp32", "sensors": {"temperature": 99}})
    readings = agent.telemetry.latest("laboratorio", "temperature", 10)
    assert len(readings) == 1 and readings[0].value == 24.7
    provider.emit("jarvis/test/devices/laboratorio/../../state", {"device_id": "laboratorio"})
    assert agent.get_device_state("laboratorio").startswith("No recibí")


def test_untrusted_discovery_cannot_receive_commands(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    agent.connect()
    provider.emit(agent.topics.discovery_topic, {"device_id": "esp32-sala", "device_type": "esp32", "capabilities": ["led"]})
    device = agent.registry.get("esp32-sala")
    assert device and not device.trusted
    provider.emit(agent.topics.device_topic("esp32-sala", "status"), "online")
    with pytest.raises(ValueError, match="no es confiable"):
        agent.send_command("esp32-sala", "set_led", {"value": True})
    assert not provider.published


def test_command_tracking_ack_and_servo_validation(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    online_device(agent, provider)
    with pytest.raises(ValueError, match="0 y 180"):
        agent.send_command("laboratorio", "set_servo", {"angle": 200})
    message = agent.send_command("laboratorio", "set_led", {"value": True})
    assert "Esperaré" in message and len(provider.published) == 1
    payload = json.loads(provider.published[-1][1])
    provider.emit(agent.topics.device_topic("laboratorio", "ack"), {"device_id": "laboratorio", "request_id": payload["request_id"], "success": True, "command": "set_led"})
    request = agent.repository.get_request(payload["request_id"])
    assert request and request.status == "acknowledged" and request.acknowledged_at
    agent.repository.save_request(IoTCommandRequest("old", "laboratorio", "set_led", utcnow().replace(year=2020)))
    assert agent.check_timeouts()[0].startswith("No recibí confirmación")


def test_state_and_rule_engine_use_cooldown_without_eval(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    online_device(agent, provider)
    created = agent.create_rule("laboratorio", "temperature", ">", 30)
    assert "Automatización creada" in created
    reading = TelemetryReading("laboratorio", "temperature", 31.4, "°C", utcnow())
    assert len(agent.rules.evaluate(reading)) == 1
    assert agent.last_alert and "31.4" in agent.last_alert
    assert not agent.rules.evaluate(reading)
    provider.emit(agent.topics.device_topic("laboratorio", "state"), {"device_id": "laboratorio", "online": True, "outputs": {"led": False}})
    assert "false" in agent.get_device_state("laboratorio", "led")
    assert agent.disable_rules("laboratorio", "temperature").startswith("Desactivé 1")


class FakeAI:
    def generate_response(self, messages: list[dict[str, str]]) -> str:
        del messages
        return "respuesta conversacional"


def test_voice_intents_route_iot_and_sensitive_actions_request_confirmation(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    router = CommandRouter(iot_agent=agent)
    assert router.route("Jarvis conecta MQTT").parsed_command == Command("iot_connect")
    assert router.route("Jarvis dime la temperatura").parsed_command.action == "iot_get_telemetry"
    rule = router.route("Jarvis avísame si la temperatura supera 30 grados").parsed_command
    assert rule and rule.action == "iot_create_rule"
    assert PermissionManager().evaluate(rule).level is SecurityLevel.CONFIRMATION
    register = router.route("Jarvis registra un ESP32 llamado laboratorio con capacidades temperature, led").parsed_command
    assert register and PermissionManager().evaluate(register).level is SecurityLevel.CONFIRMATION
    jarvis = Jarvis(FakeAI(), ConversationManager(), router, logging.getLogger("iot-test"))
    first = jarvis.process("Jarvis registra un ESP32 llamado laboratorio con capacidades temperature, led")
    assert "Confirmas" in first.response
    assert "registrado" in jarvis.process("sí").response
    agent.connect()
    provider.emit(agent.topics.device_topic("laboratorio", "status"), "online")
    relay = router.route("Jarvis enciende el relay del laboratorio").parsed_command
    assert relay and PermissionManager().evaluate(relay).level is SecurityLevel.CONFIRMATION


def test_iot_migration_and_memory_store_only_device_context(tmp_path: Path) -> None:
    database = tmp_path / "jarvis.db"
    memory_repository = MemoryRepository(database)
    memory = MemoryManager(memory_repository)
    provider = FakeMQTTProvider()
    agent = IoTAgent(provider, IoTRepository(database), memory=memory, topic_prefix="jarvis/test")
    agent.register_esp32("laboratorio", ("temperature", "led"))
    assert memory.recall("ESP32 laboratorio")
    with memory_repository._connection() as connection:  # type: ignore[attr-defined]
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"iot_devices", "iot_topics", "iot_telemetry", "iot_rules", "iot_command_history"}.issubset(tables)


def test_invalid_json_and_heartbeat_do_not_crash_iot_loop(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    online_device(agent, provider)
    provider.emit(agent.topics.device_topic("laboratorio", "telemetry"), "{broken")
    provider.emit(agent.topics.device_topic("laboratorio", "heartbeat"), {"device_id": "laboratorio", "uptime": 123, "rssi": -61})
    assert "RSSI: -61" in agent.get_device_state("laboratorio")


def test_iot_emergency_stop_has_priority_over_pending_confirmation(tmp_path: Path) -> None:
    agent, provider = make_agent(tmp_path)
    online_device(agent, provider, capabilities=("relay",))
    router = CommandRouter(iot_agent=agent)
    jarvis = Jarvis(FakeAI(), ConversationManager(), router, logging.getLogger("iot-emergency"))
    assert "Confirmas" in jarvis.process("Jarvis enciende el relay del laboratorio").response
    stopped = jarvis.process("Jarvis detén las automatizaciones IoT")
    assert "automatizaciones" in stopped.response and not provider.published


def test_code_agent_recognizes_esp32_firmware_files() -> None:
    assert detect_language(Path("firmware.ino")) == "Arduino/C++"
