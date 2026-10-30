"""Fachada v0.9: registro -> validación -> acción MQTT registrada -> ACK."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from app.iot.automations import RuleEngine
from app.iot.commands import CommandManager
from app.iot.device_manager import DeviceManager
from app.iot.discovery import DiscoveryManager
from app.iot.events import IoTEventBus
from app.iot.models import DeviceState, IoTDevice, IoTEvent, IoTEventType, MQTTConnectionState, TelemetryReading
from app.iot.mqtt_client import MQTTClient
from app.iot.mqtt_provider import MQTTProvider
from app.iot.parser import parse_ack, parse_discovery, parse_json_payload, parse_state, parse_telemetry, validate_device_identity
from app.iot.registry import DeviceRegistry
from app.iot.repository import IoTRepository
from app.iot.security import IoTCommandValidator, redact_broker
from app.iot.state import StateManager
from app.iot.telemetry import TelemetryManager
from app.iot.topics import TopicRouter
from app.memory.manager import MemoryManager


_UNITS = {"temperature": "°C", "humidity": "%", "ldr": "", "light": "", "distance": "cm"}


class IoTAgent:
    """Interfaz única usada por el router. MQTT entrante nunca pasa a Terminal ni al LLM."""

    def __init__(
        self, provider: MQTTProvider, repository: IoTRepository, *, memory: MemoryManager | None = None,
        topic_prefix: str = "jarvis", default_device: str | None = None, default_qos: int = 1,
        telemetry_retention_days: int = 30, max_payload_bytes: int = 16_384, command_timeout: int = 5,
        rule_cooldown_seconds: int = 60, logger: logging.Logger | None = None,
        alert_callback: Any | None = None, verbose_telemetry_log: bool = False, reconnect_enabled: bool = True,
        central_events: Any | None = None,
    ) -> None:
        self.logger = logger or logging.getLogger("jarvis.iot")
        self.repository = repository
        self.memory = memory
        self.default_qos = default_qos
        self.max_payload_bytes = max_payload_bytes
        self.alert_callback = alert_callback
        self.verbose_telemetry_log = verbose_telemetry_log
        self.events = IoTEventBus(self.logger)
        self.topics = TopicRouter(topic_prefix)
        self.registry = DeviceRegistry(repository, topic_prefix)
        self.mqtt = MQTTClient(provider, self.logger, reconnect_enabled=reconnect_enabled)
        self.telemetry = TelemetryManager(repository, telemetry_retention_days)
        self.states = StateManager(repository, self.registry)
        self.devices = DeviceManager(self.registry, self.states, default_device)
        self.commands = CommandManager(repository, self.mqtt, self.topics, command_timeout)
        self.rules = RuleEngine(repository, self.events, rule_cooldown_seconds)
        self.discovery = DiscoveryManager(self.registry, self.events)
        self.validator = IoTCommandValidator()
        self.last_alert: str | None = None
        self.mqtt.set_handlers(self._handle_message, self._handle_connection_state)
        for event_type in IoTEventType:
            self.events.subscribe(event_type, self.repository.log_event)
        self.events.subscribe(IoTEventType.IOT_ALERT, self._handle_alert)
        if central_events is not None:
            from app.events.models import JarvisEvent

            for event_type in IoTEventType:
                self.events.subscribe(
                    event_type,
                    lambda event: central_events.publish(
                        JarvisEvent(event.event_type.value, "iot", {**event.details, "device_id": event.device_id})
                    ),
                )

    @property
    def connection_state(self) -> MQTTConnectionState:
        return self.mqtt.state

    def connect(self) -> str:
        self.mqtt.connect()
        if self.connection_state is MQTTConnectionState.CONNECTED:
            return "MQTT conectado. Estoy suscrito a los topics registrados."
        return "Inicié la conexión MQTT en segundo plano. Te avisaré cuando el broker confirme la conexión."

    def disconnect(self) -> str:
        self.mqtt.disconnect()
        self.states.mark_connection_lost()
        return "MQTT desconectado. El estado de los actuadores se considera desconocido hasta una nueva lectura."

    def list_devices(self, *, online_only: bool = False) -> str:
        devices = [item for item in self.devices.list() if not online_only or item.status == "online"]
        if not devices:
            return "No hay dispositivos IoT registrados." if not online_only else "No hay ESP32 conectados en este momento."
        lines = []
        for item in devices:
            trust = "confiable" if item.trusted else "pendiente de autorización"
            capabilities = ", ".join(item.capabilities) or "sin capacidades declaradas"
            lines.append(f"- {item.name} ({item.id}): {item.status}, {trust}; {capabilities}.")
        return "Dispositivos IoT:\n" + "\n".join(lines)

    def register_esp32(self, name: str, capabilities: tuple[str, ...] | list[str] = ()) -> str:
        device = self.registry.register(name, device_type="esp32", capabilities=capabilities, trusted=True)
        if self.memory is not None:
            self.memory.remember(
                f"El dispositivo IoT {device.name} ({device.id}) es un ESP32 confiable con capacidades: {', '.join(device.capabilities) or 'sin declarar'}.",
                "project", key=f"iot:{device.id}", importance=0.65,
            )
        return f"ESP32 {device.name} registrado como {device.id}. Está autorizado, pero seguirá offline hasta que publique su estado MQTT."

    def get_device_state(self, reference: str | None = None, output: str | None = None) -> str:
        device, state = self.devices.health(reference)
        if state is None:
            return f"No recibí todavía un estado MQTT de {device.name}. Su conexión figura como {device.status}."
        if output:
            value = state.outputs.get(output.casefold())
            if value is None:
                return f"No tengo un estado de {output} para {device.name}."
            return f"El estado de {output} en {device.name} es {self._value(value)}."
        outputs = ", ".join(f"{key}: {self._value(value)}" for key, value in state.outputs.items()) or "sin salidas reportadas"
        last = self._age(state.updated_at)
        status = "online" if state.online is True else "offline" if state.online is False else "desconocido"
        rssi = state.details.get("rssi")
        signal = f" RSSI: {rssi} dBm." if isinstance(rssi, (int, float)) else ""
        return f"ESP32 {device.name}: {status}.{signal} Salidas: {outputs}. Última actualización: {last}."

    def get_telemetry(
        self, sensor: str | None = None, reference: str | None = None, *, limit: int = 1, maximum_today: bool = False
    ) -> str:
        device = self.devices.resolve(reference)
        if maximum_today:
            if not sensor:
                raise ValueError("Indica el sensor para calcular el máximo de hoy.")
            maximum = self.telemetry.maximum_today(device.id, sensor)
            return f"No hay lecturas de {sensor} hoy para {device.name}." if maximum is None else f"La {self._sensor_label(sensor)} máxima de hoy en {device.name} fue {maximum:g}{self._unit(sensor)}."
        readings = self.telemetry.latest(device.id, sensor, limit)
        if not readings:
            return f"No hay lecturas de {self._sensor_label(sensor) if sensor else 'telemetría'} para {device.name}."
        if limit == 1:
            reading = readings[0]
            return f"El ESP32 {device.name} reporta {self._sensor_label(reading.sensor)}: {self._value(reading.value)}{reading.unit or self._unit(reading.sensor)}. La lectura fue recibida {self._age(reading.timestamp)}."
        return "Últimas lecturas de " + device.name + ":\n" + "\n".join(
            f"- {self._sensor_label(item.sensor)}: {self._value(item.value)}{item.unit or self._unit(item.sensor)} ({self._age(item.timestamp)})" for item in readings
        )

    def send_command(self, reference: str | None, action: str, parameters: dict[str, Any] | None = None) -> str:
        device = self.devices.resolve(reference)
        validated = self.validator.validate(device, action, parameters)
        if validated.command is None:
            raise ValueError(validated.message or "El comando IoT fue bloqueado.")
        request = self.commands.send(validated.command)
        self.events.publish(IoTEvent(IoTEventType.COMMAND_SENT, device.id, {"command": action, "request_id": request.request_id}))
        timeout = threading.Timer(self.commands.timeout_seconds, self._notify_command_timeouts)
        timeout.daemon = True
        timeout.start()
        label = {"set_led": "LED", "set_relay": "relay", "set_buzzer": "buzzer", "set_servo": "servo", "get_state": "estado"}.get(action, action)
        return f"Comando {label} enviado a {device.name}. Esperaré su confirmación MQTT; no asumiré que se ejecutó hasta recibir ACK."

    def subscribe(self, reference: str | None = None) -> str:
        device = self.devices.resolve(reference)
        self._subscribe_device(device)
        return f"Suscrito a la telemetría, estado, estado de conexión y ACK de {device.name}."

    def create_rule(self, reference: str | None, sensor: str, operator: str, threshold: float, action: str = "notify") -> str:
        device = self.devices.resolve(reference)
        if device.capabilities and sensor.casefold() not in device.capabilities:
            raise ValueError(f"{device.name} no tiene el sensor {sensor} registrado.")
        rule = self.rules.create(device.id, sensor, operator, threshold, action)
        return f"Automatización creada: en {device.name}, {self._sensor_label(rule.sensor)} {rule.operator} {rule.threshold:g}{self._unit(rule.sensor)} → {self._rule_action(rule.action)}."

    def list_rules(self, reference: str | None = None) -> str:
        device_id = self.devices.resolve(reference).id if reference else None
        rules = self.rules.list(device_id)
        if not rules:
            return "No tienes automatizaciones IoT registradas."
        return "Automatizaciones IoT:\n" + "\n".join(
            f"- {rule.sensor} {rule.operator} {rule.threshold:g} en {rule.device_id} → {self._rule_action(rule.action)} ({'activa' if rule.enabled else 'desactivada'})." for rule in rules
        )

    def disable_rules(self, reference: str | None = None, sensor: str | None = None) -> str:
        device_id = self.devices.resolve(reference).id if reference else None
        count = self.rules.disable(device_id, sensor)
        return f"Desactivé {count} automatización(es) IoT." if count else "No encontré automatizaciones IoT activas que coincidan."

    def check_firmware_tools(self, terminal: object | None) -> str:
        if terminal is None:
            return "Terminal Agent no está disponible para comprobar Arduino CLI o PlatformIO."
        status = []
        for name in ("arduino-cli", "platformio"):
            try:
                result = terminal.tool_status(name)
                status.append(result.message)
            except Exception:
                status.append(f"No pude comprobar {name}.")
        return "\n".join(status) + " No compilaré ni flashearé firmware automáticamente."

    def check_timeouts(self) -> list[str]:
        expired = self.commands.expire_pending()
        return [f"No recibí confirmación del ESP32 {request.device_id} para {request.command}." for request in expired]

    def _handle_connection_state(self, state: MQTTConnectionState, reason: str | None) -> None:
        if state is MQTTConnectionState.CONNECTED:
            self.events.publish(IoTEvent(IoTEventType.IOT_CONNECTED, None, {}))
            try:
                self.mqtt.subscribe(self.topics.discovery_topic, qos=self.default_qos)
                for device in self.devices.list():
                    self._subscribe_device(device)
            except Exception as error:
                self.logger.warning("IOT subscribe failed reason=%s", type(error).__name__)
            self.logger.info("MQTT connected")
        elif state in {MQTTConnectionState.DISCONNECTED, MQTTConnectionState.RECONNECTING}:
            self.states.mark_connection_lost()
            self.events.publish(IoTEvent(IoTEventType.IOT_DISCONNECTED, None, {"reason": reason or ""}))
            self.logger.info("MQTT %s reason=%s", state.value, reason or "unspecified")

    def _subscribe_device(self, device: IoTDevice) -> None:
        for purpose in ("telemetry", "state", "status", "ack", "heartbeat"):
            self.mqtt.subscribe(self.topics.device_topic(device.id, purpose), qos=self.default_qos)

    def _handle_message(self, topic: str, payload: bytes) -> None:
        routed = self.topics.route(topic)
        if routed is None:
            self.logger.warning("IOT message rejected reason=unmanaged_topic")
            return
        try:
            if routed.purpose == "status" and routed.device_id is not None:
                plain_status = payload.decode("utf-8").strip().casefold()
                if plain_status in {"online", "offline"}:
                    if self.registry.get(routed.device_id) is None:
                        raise ValueError("El dispositivo no está registrado.")
                    self.registry.touch(routed.device_id, plain_status, datetime.now(timezone.utc))
                    self.events.publish(IoTEvent(IoTEventType.DEVICE_ONLINE if plain_status == "online" else IoTEventType.DEVICE_OFFLINE, routed.device_id, {}))
                    return
            data = parse_json_payload(payload, self.max_payload_bytes)
            if routed.purpose == "discovery":
                identifier, device_type, capabilities = parse_discovery(data)
                device, new = self.discovery.announce(identifier, device_type, capabilities)
                if new:
                    self.logger.info("IOT discovery id=%s trusted=false", device.id)
                return
            if routed.device_id is None or self.registry.get(routed.device_id) is None:
                raise ValueError("El dispositivo no está registrado.")
            if routed.purpose == "telemetry":
                readings = parse_telemetry(data, routed.device_id)
                self.registry.touch(routed.device_id, "online", readings[0].timestamp)
                for reading in readings:
                    self.telemetry.record(reading)
                    self.events.publish(IoTEvent(IoTEventType.TELEMETRY_RECEIVED, reading.device_id, {"sensor": reading.sensor}))
                    if self.verbose_telemetry_log:
                        self.logger.info("TELEMETRY device=%s sensor=%s", reading.device_id, reading.sensor)
                    self.rules.evaluate(reading)
                return
            if routed.purpose == "state":
                state = self.states.update(parse_state(data, routed.device_id))
                self.events.publish(IoTEvent(IoTEventType.STATE_CHANGED, state.device_id, {"online": state.online}))
                return
            if routed.purpose == "ack":
                ack = parse_ack(data, routed.device_id)
                saved = self.commands.acknowledge(ack.request_id, ack.device_id, ack.command, ack.status == "acknowledged")
                if saved:
                    self.events.publish(IoTEvent(IoTEventType.COMMAND_ACKNOWLEDGED, saved.device_id, {"command": saved.command, "success": saved.status == "acknowledged"}))
                return
            validate_device_identity(data, routed.device_id)
            online = data.get("online", data.get("status"))
            if online in {True, "online"}:
                self.registry.touch(routed.device_id, "online", datetime.now(timezone.utc))
                self.events.publish(IoTEvent(IoTEventType.DEVICE_ONLINE, routed.device_id, {}))
            elif online in {False, "offline"}:
                self.registry.touch(routed.device_id, "offline", datetime.now(timezone.utc))
                self.events.publish(IoTEvent(IoTEventType.DEVICE_OFFLINE, routed.device_id, {}))
            elif routed.purpose == "heartbeat":
                previous = self.states.get(routed.device_id)
                heartbeat = DeviceState(
                    routed.device_id, True, previous.outputs if previous else {}, datetime.now(timezone.utc),
                    {key: value for key, value in data.items() if key != "device_id"},
                )
                self.states.update(heartbeat)
        except ValueError as error:
            self.logger.warning("IOT message rejected topic=%s reason=%s", topic, str(error))
        except Exception as error:
            self.logger.warning("IOT message processing failed topic=%s reason=%s", topic, type(error).__name__)

    def _handle_alert(self, event: IoTEvent) -> None:
        rule = event.details.get("rule")
        reading = event.details.get("reading")
        if rule is None or not isinstance(reading, TelemetryReading):
            return
        device = self.registry.get(reading.device_id)
        name = device.name if device else reading.device_id
        if rule.action == "notify":
            message = f"Alerta: el ESP32 {name} reporta {self._value(reading.value)}{reading.unit or self._unit(reading.sensor)} de {self._sensor_label(reading.sensor)}."
        else:
            validated = self.validator.validate(device, "set_led", {"value": rule.action.endswith(":on")}) if device else None
            if validated is None or validated.command is None:
                return
            try:
                self.commands.send(validated.command)
                message = f"Automatización IoT: envié {rule.action} a {name}. Esperaré su ACK."
            except (ConnectionError, ValueError) as error:
                message = f"Automatización IoT no ejecutada: {error}"
        self._deliver_alert(message)

    def _notify_command_timeouts(self) -> None:
        try:
            for message in self.check_timeouts():
                self._deliver_alert(message)
        except Exception as error:
            self.logger.warning("IOT command timeout check skipped reason=%s", type(error).__name__)

    def _deliver_alert(self, message: str) -> None:
        self.last_alert = message
        self.logger.info("IOT alert delivered")
        if self.alert_callback:
            threading.Thread(target=self.alert_callback, args=(message,), daemon=True).start()

    @staticmethod
    def _value(value: object) -> str:
        return f"{value:g}" if isinstance(value, float) else str(value).lower() if isinstance(value, bool) else str(value)

    @staticmethod
    def _sensor_label(sensor: str | None) -> str:
        labels = {"temperature": "temperatura", "humidity": "humedad", "ldr": "LDR", "light": "luz", "distance": "distancia"}
        return labels.get(sensor or "", sensor or "telemetría")

    @staticmethod
    def _unit(sensor: str) -> str:
        return _UNITS.get(sensor, "")

    @staticmethod
    def _rule_action(action: str) -> str:
        return {"notify": "avisar", "set_led:on": "encender LED", "set_led:off": "apagar LED"}.get(action, action)

    @staticmethod
    def _age(value: datetime) -> str:
        seconds = max(0, int((datetime.now(timezone.utc) - value).total_seconds()))
        if seconds < 60:
            return f"hace {seconds} segundos"
        if seconds < 3600:
            return f"hace {seconds // 60} minutos"
        return f"hace {seconds // 3600} horas"
