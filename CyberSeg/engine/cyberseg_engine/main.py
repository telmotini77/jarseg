from __future__ import annotations

import logging
import os
import signal
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from cyberseg_engine.analyzer import TrafficAnalyzer
from cyberseg_engine.audit import ServerAuditor
from cyberseg_engine.config import EngineConfig
from cyberseg_engine.detections import NetworkContext, build_detectors
from cyberseg_engine.detector import AnomalyDetector
from cyberseg_engine.dissect import CAPTURE_FILTER, dissect
from cyberseg_engine.models import Observation, utcnow
from cyberseg_engine.publisher import AlertPublisher, AlertQueue
from cyberseg_engine.responder import BlockPolicy, FirewallError, NftablesFirewall, Responder, read_nameservers
from cyberseg_engine.segmenter import TimeWindowSegmenter
from cyberseg_engine.suricata import EveFollower, SuricataAlertMapper, SuricataSource

LOGGER = logging.getLogger("cyberseg.engine")


def _interface_problem(interface: str) -> str | None:
    from scapy.all import get_if_list  # Imported only after explicit operator enablement.

    available = get_if_list()
    if interface not in available:
        return f"La interfaz {interface!r} no existe en este equipo. Disponibles: {', '.join(available)}."
    return None


def _network_context(interface: str, trusted: tuple[str, ...]) -> NetworkContext:
    addresses: set[str] = set()
    gateway = ""
    if interface:
        try:
            from scapy.all import conf, get_if_addr, in6_getifaddr

            address = get_if_addr(interface)
            if address and address != "0.0.0.0":
                addresses.add(address)
            addresses.update(address for address, _scope, name in in6_getifaddr() if name == interface)
            # The next hop towards any Internet address is the default gateway.
            gateway = str(conf.route.route("1.1.1.1")[2] or "")
        except Exception:
            LOGGER.warning("No se pudieron leer las direcciones de %s.", interface)
    return NetworkContext(frozenset(addresses), "" if gateway == "0.0.0.0" else gateway, trusted)


def _capture_filter(interface: str) -> str | None:
    from scapy.arch.common import compile_filter

    try:
        compile_filter(CAPTURE_FILTER, iface=interface)
        return CAPTURE_FILTER
    except Exception as error:  # libpcap missing or unusable: filter in Python instead.
        LOGGER.warning("Filtro BPF no disponible (%s); se filtrará en el motor.", error)
        return None


def _sniffer(interface: str, callback: Callable[[list[Observation]], None]):
    from scapy.all import AsyncSniffer

    failures = 0

    def observe(packet) -> None:
        # An exception here would kill scapy's capture thread silently.
        nonlocal failures
        try:
            observations = dissect(packet)
            if observations:
                callback(observations)
        except Exception:
            failures += 1
            if failures == 1 or failures % 1000 == 0:
                LOGGER.exception("Error procesando un paquete (%s errores en total).", failures)

    return AsyncSniffer(iface=interface, filter=_capture_filter(interface), prn=observe, store=False)


class CaptureController:
    """Start/stop the sniffer to match the backend's requested state."""

    RESTART_DELAY_SECONDS = 10

    def __init__(self, interface: str, analyzer: TrafficAnalyzer) -> None:
        self.interface = interface
        self.analyzer = analyzer
        self.last_error: str | None = None
        self._sniffer = None
        self._next_start = 0.0

    @property
    def capturing(self) -> bool:
        thread = getattr(self._sniffer, "thread", None)
        return thread is not None and thread.is_alive()

    def reconcile(self, requested: bool) -> None:
        if self.capturing:
            self.last_error = None
        elif self._sniffer is not None:
            error = getattr(self._sniffer, "exception", None)
            self.last_error = f"La captura en {self.interface} se detuvo: {error or 'motivo desconocido'}"[:300]
            LOGGER.error("%s. Reintento en %ss.", self.last_error, self.RESTART_DELAY_SECONDS)
            self._sniffer = None
            self._next_start = time.monotonic() + self.RESTART_DELAY_SECONDS
        if requested and self._sniffer is None and time.monotonic() >= self._next_start:
            self._sniffer = _sniffer(self.interface, self.analyzer.process)
            self._sniffer.start()
            LOGGER.info("CyberSeg captura local iniciada en %s.", self.interface)
        elif not requested and self._sniffer is not None:
            self.stop()
            LOGGER.info("CyberSeg captura detenida por el controlador local.")

    def stop(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as error:
                LOGGER.warning("La captura ya estaba detenida: %s", error)
        self.analyzer.flush()


class AuditScheduler:
    """Re-run the server audit periodically and sync its findings."""

    def __init__(self, auditor: ServerAuditor, submit: Callable[[str, list], None], interval_hours: int) -> None:
        self._auditor = auditor
        self._submit = submit
        self._interval = interval_hours * 3600
        self._stop = threading.Event()
        self.last_run_at: str | None = None
        self.findings = 0

    def start(self) -> None:
        threading.Thread(target=self._run, name="cyberseg-audit", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        self._stop.wait(5)  # let the API come up first
        while not self._stop.is_set():
            try:
                findings = self._auditor.run()
                self._submit("audit", findings)
                self.findings = len(findings)
                self.last_run_at = datetime.now(timezone.utc).isoformat()
                LOGGER.info("Auditoría del servidor completada: %s hallazgos.", len(findings))
            except Exception:
                LOGGER.exception("La auditoría del servidor falló.")
            self._stop.wait(self._interval)


def _build_responder(config: EngineConfig, context: NetworkContext, alerts: AlertQueue) -> tuple[Responder | None, str]:
    if config.prevention_mode == "alert":
        return None, "alert"
    firewall = NftablesFirewall()
    if config.prevention_mode == "block":
        if not firewall.available():
            LOGGER.error("Prevención desactivada: no se encontró el comando nft en el motor.")
            return None, "unavailable"
        try:
            firewall.setup()
        except (FirewallError, OSError) as error:
            LOGGER.error("Prevención desactivada: no se pudo preparar nftables (%s). ¿Tiene el contenedor NET_ADMIN?", error)
            return None, "unavailable"
    policy = BlockPolicy(
        mode=config.prevention_mode, min_severity=config.block_min_severity, base_seconds=config.block_seconds,
        max_seconds=config.block_max_seconds, block_private=config.block_private,
        trusted_networks=config.trusted_networks, protected_addresses=read_nameservers(),
    )
    responder = Responder(firewall, policy, context, report_block=alerts.submit_block)
    if config.prevention_mode == "block":
        responder.restore(firewall.existing())
    LOGGER.info(
        "Prevención %s: bloqueo de IPs con riesgo >= %s durante %ss (redes de confianza: %s).",
        "ACTIVA" if config.prevention_mode == "block" else "en simulación (dry-run)",
        config.block_min_severity, config.block_seconds, ", ".join(config.trusted_networks) or "ninguna",
    )
    return responder, config.prevention_mode


def main() -> None:
    logging.basicConfig(
        level=os.getenv("CYBERSEG_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = EngineConfig.from_env()
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: stop.set())

    publisher = AlertPublisher(config.api_url, config.token)
    alerts = AlertQueue(publisher)
    problem: str | None = None
    if not config.capture_allowed:
        problem = "Captura no autorizada: CYBERSEG_CAPTURE_ALLOWED=false."
    elif not config.interface:
        problem = "Define CYBERSEG_INTERFACE antes de habilitar captura."
    else:
        problem = _interface_problem(config.interface)
    context = _network_context(config.interface if problem is None else "", config.trusted_networks)

    responder, prevention = _build_responder(config, context, alerts)
    if responder is not None:
        alerts.respond = responder.handle
    alerts.start()

    suricata: SuricataSource | None = None
    if config.suricata_enabled:
        suricata = SuricataSource(
            EveFollower(config.suricata_eve, socket_path=config.suricata_socket),
            SuricataAlertMapper(min_severity=config.suricata_min_severity, cooldown_seconds=config.alert_cooldown_seconds),
            alerts.submit,
        )
        suricata.start()

    audit: AuditScheduler | None = None
    if config.audit_enabled:
        host = next(iter(sorted(context.local_addresses)), "este servidor")
        audit = AuditScheduler(ServerAuditor(ssh_dir=config.ssh_config_dir, host_label=host), alerts.submit_findings_sync, config.audit_interval_hours)
        audit.start()

    controller: CaptureController | None = None
    if problem is None:
        detectors = build_detectors(
            config.detection, context, scan=config.scan, scan_allowlist=config.allowlist, dhcp_servers=config.dhcp_servers,
        )
        analyzer = TrafficAnalyzer(
            alerts.submit, emit_finding=alerts.submit_finding, segmenter=TimeWindowSegmenter(config.window_seconds),
            anomaly=AnomalyDetector(config.contamination), detectors=detectors, context=context, settings=config.detection,
            baseline_min_samples=config.baseline_min_samples, baseline_min_windows=config.baseline_min_windows,
            alert_cooldown_seconds=config.alert_cooldown_seconds,
        )
        controller = CaptureController(config.interface, analyzer)
        LOGGER.info(
            "Motor listo en %s (%s): %s detectores L2-L7, puerta de enlace %s.",
            config.interface, ", ".join(sorted(context.local_addresses)) or "sin IP", len(detectors), context.gateway_ip or "desconocida",
        )
    else:
        LOGGER.warning("Captura del motor inactiva: %s", problem)

    started_at = utcnow().isoformat()
    api_online: bool | None = None
    requested = False
    try:
        while not stop.is_set():
            status: dict[str, object] = {
                "captureAllowed": config.capture_allowed,
                "capturing": controller is not None and controller.capturing,
                "interface": config.interface,
                "alertsPublished": alerts.published,
                "alertsFailed": alerts.failed,
                "alertsDropped": alerts.dropped,
                "lastError": problem or (controller.last_error if controller else None),
                "startedAt": started_at,
                "prevention": {
                    "mode": prevention,
                    "activeBlocks": responder.active_blocks if responder else 0,
                    "blocksApplied": responder.blocks_applied if responder else 0,
                    "minSeverity": config.block_min_severity,
                },
                "suricata": {"enabled": config.suricata_enabled, **(suricata.snapshot() if suricata else {})},
                "audit": {"enabled": config.audit_enabled, "lastRunAt": audit.last_run_at if audit else None, "findings": audit.findings if audit else 0},
                **(controller.analyzer.snapshot() if controller else {}),
            }
            try:
                # Transient API outages keep the last requested state: capture
                # only stops when the controller explicitly asks for it.
                reply = publisher.heartbeat(status)
                requested = bool(reply.get("captureEnabled"))
                for address in reply.get("unblock") or []:
                    if responder is not None:
                        try:
                            responder.unblock(str(address))
                        except FirewallError as error:
                            LOGGER.error("No se pudo desbloquear %s: %s", address, error)
                if api_online is not True:
                    LOGGER.info("Conectado a la API de CyberSeg (%s). Captura solicitada: %s.", config.api_url, requested)
                api_online = True
            except ConnectionError as error:
                if api_online is not False:
                    LOGGER.error("%s Se reintentará cada %ss.", error, config.heartbeat_seconds)
                api_online = False
            if controller is not None:
                controller.reconcile(requested)
                controller.analyzer.tick()
            stop.wait(config.heartbeat_seconds)
    finally:
        if controller is not None:
            controller.stop()
        if suricata is not None:
            suricata.stop()
        if audit is not None:
            audit.stop()
        alerts.stop()
        LOGGER.info("CyberSeg engine detenido.")


if __name__ == "__main__":
    main()
