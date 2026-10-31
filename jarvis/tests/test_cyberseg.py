from __future__ import annotations

from app.commands.base import Command
from app.commands.router import CommandRouter
from app.cyberseg.client import CyberSegClient, CyberSegClientError
from app.cyberseg.monitor import CyberSegMonitor
from app.cyberseg.threat_intelligence import coverage_report, enrich_alerts
from app.input.headless import HeadlessDesktopBackend
from app.input.keyboard import KeyboardController
from app.input.mouse import MouseController
from app.security.permissions import PermissionManager, SecurityLevel


class FakeCyberSeg:
    def status(self) -> str:
        return "CyberSeg ONLINE. Captura local detenida."

    def recent_alerts(self, limit: int = 5) -> str:
        return f"Alertas: {limit}"

    def start_capture(self) -> str:
        return "Captura iniciada"

    def stop_capture(self) -> str:
        return "Captura detenida"


def test_cyberseg_client_rejects_non_local_endpoints() -> None:
    try:
        CyberSegClient("https://example.com", "token")
    except ValueError as error:
        assert "local" in str(error)
    else:
        raise AssertionError("CyberSeg must not accept a remote API endpoint")


def test_cyberseg_client_accepts_docker_host_bridge() -> None:
    client = CyberSegClient("http://host.docker.internal:8780", "token")
    assert client.api_url == "http://host.docker.internal:8780"


def test_cyberseg_defensive_taxonomy_enriches_alerts_without_attack_content() -> None:
    enriched = enrich_alerts("- [HIGH] 8.8.8.8 → 10.0.0.1: ransomware and phishing indicators")

    assert "Malware y ransomware" in enriched
    assert "Suplantación y phishing" in enriched
    assert "no ejecuta ni genera ataques" in coverage_report()


def test_cyberseg_monitor_notifies_new_alerts_after_an_empty_baseline() -> None:
    class MonitorClient:
        def __init__(self) -> None:
            self.alerts = "CyberSeg no tiene alertas registradas."

        def status(self) -> str:
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return self.alerts

    client = MonitorClient()
    messages: list[str] = []
    monitor = CyberSegMonitor(client, messages.append)
    monitor.poll_once()
    client.alerts = "[2026-09-11] severidad=high tipo=scan"
    monitor.poll_once()

    assert messages == ["Vulneración detectada por CyberSeg:\n[2026-09-11] severidad=high tipo=scan"]


def test_cyberseg_monitor_keeps_clean_and_low_risk_reviews_out_of_telegram() -> None:
    class MonitorClient:
        def __init__(self) -> None:
            self.alerts = "CyberSeg no tiene alertas registradas."

        def status(self) -> str:
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return self.alerts

    client = MonitorClient()
    messages: list[str] = []
    monitor = CyberSegMonitor(client, messages.append, minimum_risk="high", clean_report_seconds=0)
    monitor.poll_once()
    client.alerts = "Alertas recientes de CyberSeg:\n- [LOW] 8.8.8.8 → 10.0.0.1: tráfico revisado"
    monitor.poll_once()
    client.alerts = "Alertas recientes de CyberSeg:\n- [HIGH] 8.8.8.8 → 10.0.0.1: intento de vulneración"
    monitor.poll_once()

    assert messages == [
        "Vulneración detectada por CyberSeg:\n- [HIGH] 8.8.8.8 → 10.0.0.1: intento de vulneración"
    ]


def test_cyberseg_monitor_reports_a_clean_review_once_per_interval() -> None:
    class MonitorClient:
        def status(self) -> str:
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return "CyberSeg no tiene alertas registradas."

    messages: list[str] = []
    monitor = CyberSegMonitor(MonitorClient(), messages.append, clean_report_seconds=3_600)
    monitor.poll_once()
    monitor.poll_once()

    assert messages == [
        "Revisión de radar y sistema completada: no se detectaron interferencias ni vulnerabilidades de riesgo alto o crítico."
    ]


def test_cyberseg_monitor_labels_high_risk_interference_for_telegram() -> None:
    class MonitorClient:
        def __init__(self) -> None:
            self.alerts = "CyberSeg no tiene alertas registradas."

        def status(self) -> str:
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return self.alerts

    client = MonitorClient()
    messages: list[str] = []
    monitor = CyberSegMonitor(client, messages.append)
    monitor.poll_once()
    client.alerts = "- [HIGH] Interferencia de radio detectada cerca del enlace."
    monitor.poll_once()

    assert messages == [
        "Interferencia detectada por CyberSeg:\n- [HIGH] Interferencia de radio detectada cerca del enlace."
    ]


def test_cyberseg_monitor_reports_unavailable_then_recovery() -> None:
    class MonitorClient:
        available = False

        def status(self) -> str:
            if not self.available:
                raise CyberSegClientError("offline")
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return "CyberSeg no tiene alertas registradas."

    client = MonitorClient()
    messages: list[str] = []
    monitor = CyberSegMonitor(client, messages.append, notify_service_state=True, retry_attempts=0, failure_threshold=1)
    monitor.poll_once()
    monitor.poll_once()
    client.available = True
    monitor.poll_once()

    assert messages == [
        "CyberSeg no está disponible. JARVIS seguirá reintentando en segundo plano.",
        "CyberSeg volvió a estar disponible. CyberSeg ONLINE.",
    ]


def test_cyberseg_monitor_retries_transient_service_failure_before_marking_it_down() -> None:
    class MonitorClient:
        calls = 0

        def status(self) -> str:
            self.calls += 1
            if self.calls == 1:
                raise CyberSegClientError("temporary")
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return "CyberSeg no tiene alertas registradas."

    client = MonitorClient()
    messages: list[str] = []
    monitor = CyberSegMonitor(client, messages.append, retry_attempts=1)
    monitor.poll_once()

    assert client.calls == 2
    assert messages == []


def test_cyberseg_monitor_requires_multiple_failed_cycles_before_outage_alert() -> None:
    class MonitorClient:
        def status(self) -> str:
            raise CyberSegClientError("offline")

    messages: list[str] = []
    monitor = CyberSegMonitor(MonitorClient(), messages.append, notify_service_state=True, retry_attempts=0, failure_threshold=3)
    monitor.poll_once()
    monitor.poll_once()
    assert messages == []
    monitor.poll_once()

    assert messages == ["CyberSeg no está disponible. JARVIS seguirá reintentando en segundo plano."]


def test_cyberseg_status_keeps_service_online_when_engine_state_is_temporarily_unavailable(monkeypatch) -> None:
    client = CyberSegClient("http://127.0.0.1:8780", "token")

    def request(_self, path: str, **_kwargs) -> object:
        if path == "/health":
            return {"status": "online"}
        raise CyberSegClientError("engine temporarily unavailable")

    monkeypatch.setattr(CyberSegClient, "_request", request)
    assert client.status() == "CyberSeg ONLINE. Estado de captura no disponible temporalmente."


def test_cyberseg_status_reports_engine_capture_progress(monkeypatch) -> None:
    client = CyberSegClient("http://127.0.0.1:8780", "token")
    engine = {"online": True, "capturing": True, "interface": "eth0", "packetsSeen": 1200, "portScansDetected": 2}

    def request(_self, path: str, **_kwargs) -> object:
        return {"status": "online"} if path == "/health" else {"captureEnabled": True, "engine": engine}

    monkeypatch.setattr(CyberSegClient, "_request", request)
    assert client.status() == (
        "CyberSeg ONLINE. Captura local activa. Motor capturando en eth0: 1200 paquetes analizados, "
        "2 escaneos de puertos detectados."
    )
    engine.update(prevention={"mode": "block", "activeBlocks": 3}, suricata={"enabled": True, "connected": True})
    assert client.status().endswith("Prevención activa: 3 IPs bloqueadas. Suricata conectado.")
    engine.update(online=False)
    assert client.status() == "CyberSeg ONLINE. Captura local activa. El motor de captura no responde."


def test_cyberseg_monitor_silences_service_state_by_default() -> None:
    class MonitorClient:
        available = False

        def status(self) -> str:
            if not self.available:
                raise CyberSegClientError("offline")
            return "CyberSeg ONLINE."

        def recent_alerts(self, limit: int = 5) -> str:
            return "CyberSeg no tiene alertas registradas."

    client = MonitorClient()
    messages: list[str] = []
    monitor = CyberSegMonitor(client, messages.append)
    monitor.poll_once()
    client.available = True
    monitor.poll_once()

    assert messages == []


def test_headless_service_input_backend_blocks_desktop_control() -> None:
    backend = HeadlessDesktopBackend()
    mouse = MouseController(backend=backend)
    keyboard = KeyboardController(backend=backend)

    assert mouse.screen_size() == (1, 1)
    assert mouse.click(0, 0).success is False
    assert keyboard.press_key("enter").success is False


def test_router_parses_cyberseg_commands() -> None:
    router = CommandRouter(cyberseg_client=FakeCyberSeg())
    assert router.route("Jarvis dime el estado de CyberSeg").parsed_command == Command("cyberseg_status")
    alerts = router.route("Jarvis revisa CyberSeg y dime qué quedó pendiente").parsed_command
    assert alerts is not None and alerts.action == "cyberseg_alerts"
    assert router.execute(Command("cyberseg_alerts", arguments={"limit": 5})).message == "Alertas: 5"
    coverage = router.route("Jarvis muéstrame el entrenamiento de CyberSeg").parsed_command
    assert coverage == Command("cyberseg_threat_coverage")
    assert "Cobertura defensiva" in router.execute(coverage).message


def test_cyberseg_capture_start_requires_confirmation() -> None:
    decision = PermissionManager().evaluate(Command("cyberseg_start_capture"))
    assert decision.level is SecurityLevel.CONFIRMATION
