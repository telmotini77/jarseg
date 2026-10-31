import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cyberseg_engine.analyzer import TrafficAnalyzer
from cyberseg_engine.detections import NetworkContext, build_detectors
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.detector import AnomalyDetector
from cyberseg_engine.models import TCP_ACK, TCP_SYN, DetectionAlert, PacketObservation
from cyberseg_engine.publisher import AlertPublisher, AlertQueue
from cyberseg_engine.segmenter import TimeWindowSegmenter

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def analyzer(emitted: list, findings: list | None = None, *, window_seconds: int = 10, settings: DetectionSettings | None = None) -> TrafficAnalyzer:
    settings = settings or DetectionSettings()
    context = NetworkContext(frozenset({"198.51.100.10"}))
    return TrafficAnalyzer(
        emitted.append, emit_finding=(findings if findings is not None else []).append,
        segmenter=TimeWindowSegmenter(window_seconds), anomaly=AnomalyDetector(),
        detectors=build_detectors(settings, context), context=context, settings=settings,
        baseline_min_samples=8, baseline_min_windows=2,
    )


def test_port_scan_is_reported_without_a_trained_model() -> None:
    emitted: list = []
    engine = analyzer(emitted)
    for port in range(1, 40):
        engine.process(PacketObservation(NOW, "203.0.113.9", "198.51.100.10", 50000, port, "tcp", 60, TCP_SYN))

    assert [alert.rule_id for alert in emitted] == ["L4-PORTSCAN"]
    assert emitted[0].mitre == "T1046" and emitted[0].layer == "L4"
    assert engine.snapshot()["portScansDetected"] == 1
    assert engine.snapshot()["anomalyModelTrained"] is False


def test_windows_close_on_time_and_train_the_model() -> None:
    emitted: list = []
    engine = analyzer(emitted)
    for window in range(2):
        start = NOW + timedelta(seconds=window * 20)
        for client in range(10):
            engine.process(PacketObservation(start, f"10.0.0.{client}", "10.0.0.1", 50000, 443, "tcp", 500, TCP_ACK))
        engine.tick(start + timedelta(seconds=11))

    snapshot = engine.snapshot()
    assert snapshot["anomalyModelTrained"] is True
    assert snapshot["packetsSeen"] == 20


def test_large_upload_to_the_internet_is_flagged_as_possible_exfiltration() -> None:
    emitted: list = []
    engine = analyzer(emitted, settings=DetectionSettings(exfil_mb=1))
    for index in range(1000):
        engine.process(PacketObservation(NOW + timedelta(milliseconds=index), "198.51.100.10", "93.184.216.34", 50000, 443, "tcp", 1500, TCP_ACK))
    engine.tick(NOW + timedelta(seconds=11))

    assert [alert.rule_id for alert in emitted] == ["L4-EXFIL-VOLUME"]
    assert emitted[0].blockable is False


def test_every_detector_accepts_every_observation_type() -> None:
    from cyberseg_engine.models import ArpObservation, DnsObservation, FragmentObservation, IcmpObservation

    emitted: list = []
    engine = analyzer(emitted)
    for observation in (
        ArpObservation(NOW, 1, "10.0.0.5", "aa:bb:cc:dd:ee:ff", "10.0.0.1"),
        IcmpObservation(NOW, "10.0.0.5", "10.0.0.9", 8, 0, 84),
        DnsObservation(NOW, "10.0.0.5", "10.0.0.1", "example.com.", 1, False, 0, 70),
        FragmentObservation(NOW, "10.0.0.5", "10.0.0.9", 0, True, 400, 17),
        PacketObservation(NOW, "10.0.0.5", "10.0.0.9", 40000, 53, "udp", 70),
    ):
        engine.process(observation)
    assert engine.detector_errors == 0


def test_a_failing_detector_does_not_stop_the_others() -> None:
    class Broken:
        def observe(self, _observation):
            raise RuntimeError("boom")

    emitted: list = []
    engine = analyzer(emitted)
    engine._detectors.insert(0, Broken())
    for port in range(1, 20):
        engine.process(PacketObservation(NOW, "203.0.113.9", "198.51.100.10", 50000, port, "tcp", 60, TCP_SYN))

    assert len(emitted) == 1 and engine.detector_errors == 19


class _Api(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).received.append((self.path, self.headers["X-CyberSeg-Engine-Token"], body))
        reply = {"captureEnabled": True, "unblock": ["203.0.113.66"]} if self.path == "/api/engine/heartbeat" else {"id": "1"}
        payload = json.dumps(reply).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:
        pass


def test_publisher_runs_the_response_before_publishing_alerts() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        publisher = AlertPublisher(f"http://127.0.0.1:{server.server_port}", "secret")
        assert publisher.heartbeat({"capturing": True}) == {"captureEnabled": True, "unblock": ["203.0.113.66"]}

        emitted: list = []
        engine = analyzer(emitted)
        for port in range(1, 20):
            engine.process(PacketObservation(NOW, "203.0.113.9", "198.51.100.10", 50000, port, "tcp", 60, TCP_SYN))

        def respond(alert: DetectionAlert) -> DetectionAlert:
            queue.submit_block({"ip": alert.source_ip})
            return alert.__class__(**{**{f: getattr(alert, f) for f in alert.__dataclass_fields__}, "action": "blocked"})

        queue = AlertQueue(publisher, respond=respond)
        queue.start()
        for alert in emitted:
            queue.submit(alert)
        queue.stop()

        assert queue.published == 1
        paths = [path for path, token, _body in _Api.received if token == "secret"]
        assert paths == ["/api/engine/heartbeat", "/api/alerts", "/api/blocks"]
        alert_body = _Api.received[1][2]
        assert alert_body["risk"] == "high" and alert_body["action"] == "blocked" and alert_body["mitre"] == "T1046"
    finally:
        server.shutdown()
