from __future__ import annotations

import logging
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from datetime import datetime

from cyberseg_engine.detections.base import Cooldown, NetworkContext, alert, is_private, is_public
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.detector import AnomalyDetector
from cyberseg_engine.models import DetectionAlert, Finding, Observation, PacketObservation, TrafficFeature, utcnow
from cyberseg_engine.segmenter import TimeWindowSegmenter


class TrafficAnalyzer:
    """Feed captured traffic to every detector and to the anomaly model.

    ``process`` runs on the sniffer thread and ``tick`` on the main loop, so all
    state is guarded by one lock. ``emit``/``emit_finding`` must not block (the
    engine hands them to a background publishing queue).
    """

    def __init__(
        self,
        emit: Callable[[DetectionAlert], None],
        *,
        segmenter: TimeWindowSegmenter,
        anomaly: AnomalyDetector,
        detectors: list,
        emit_finding: Callable[[Finding], None] | None = None,
        context: NetworkContext | None = None,
        settings: DetectionSettings | None = None,
        baseline_min_samples: int = 64,
        baseline_min_windows: int = 3,
        alert_cooldown_seconds: int = 600,
        logger: logging.Logger | None = None,
    ) -> None:
        self._emit = emit
        self._emit_finding = emit_finding or (lambda _finding: None)
        self._segmenter = segmenter
        self._anomaly = anomaly
        self._detectors = detectors
        self._context = context or NetworkContext()
        self._settings = settings or DetectionSettings()
        self._baseline_min_samples = baseline_min_samples
        self._baseline_min_windows = baseline_min_windows
        self._cooldown_seconds = alert_cooldown_seconds
        self._logger = logger or logging.getLogger("cyberseg.engine.analyzer")
        self._lock = threading.Lock()
        self._baseline: list[TrafficFeature] = []
        self._baseline_windows = 0
        self._recent_anomalies: dict[tuple[str, str, int], float] = {}
        self._exfil_cooldown = Cooldown(3600)
        self.packets_seen = 0
        self.findings_reported = 0
        self.detections: Counter[str] = Counter()
        self.detector_errors = 0

    @property
    def port_scans_detected(self) -> int:
        return self.detections["reconnaissance:L4"]

    def process(self, observations: Observation | Iterable[Observation]) -> None:
        """Analyse the observations produced by one captured packet."""
        batch = [observations] if not isinstance(observations, (list, tuple)) else observations
        with self._lock:
            self.packets_seen += 1
            for observation in batch:
                for detector in self._detectors:
                    try:
                        results = detector.observe(observation)
                    except Exception:
                        # One faulty rule must never stop the others.
                        self.detector_errors += 1
                        if self.detector_errors == 1 or self.detector_errors % 1000 == 0:
                            self._logger.exception("Error en %s", type(detector).__name__)
                        continue
                    for result in results:
                        self._dispatch(result)
                if isinstance(observation, PacketObservation):
                    self._analyse_window(self._segmenter.add(observation))

    def tick(self, now: datetime | None = None) -> None:
        with self._lock:
            self._analyse_window(self._segmenter.flush_expired(now or utcnow()))

    def flush(self) -> None:
        with self._lock:
            self._analyse_window(self._segmenter.flush())

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "packetsSeen": self.packets_seen,
                "portScansDetected": self.port_scans_detected,
                "anomaliesDetected": self.detections["anomaly:L4"],
                "detectionsTotal": sum(self.detections.values()),
                "findingsReported": self.findings_reported,
                "anomalyModelTrained": self._anomaly.trained,
                "baselineSamples": len(self._baseline),
            }

    def _dispatch(self, result: DetectionAlert | Finding) -> None:
        if isinstance(result, Finding):
            self.findings_reported += 1
            self._logger.warning("Vulnerabilidad observada: %s (%s)", result.title, result.asset)
            self._emit_finding(result)
            return
        self.detections[f"{result.category}:{result.layer}"] += 1
        self._logger.warning("[%s] %s", result.risk.upper(), result.description)
        self._emit(result)

    def _analyse_window(self, features: list[TrafficFeature]) -> None:
        if not features:
            return
        self._check_exfiltration(features)
        if not self._anomaly.trained:
            self._baseline.extend(features)
            self._baseline_windows += 1
            if len(self._baseline) >= self._baseline_min_samples and self._baseline_windows >= self._baseline_min_windows:
                self._anomaly.train(self._baseline)
                self._logger.info("Modelo de anomalías entrenado con %s flujos de %s ventanas.", len(self._baseline), self._baseline_windows)
                self._baseline = self._baseline[-self._baseline_min_samples:]
            return
        now = time.monotonic()
        if len(self._recent_anomalies) > 10_000:
            self._recent_anomalies = {key: at for key, at in self._recent_anomalies.items() if now - at < self._cooldown_seconds}
        for found in self._anomaly.detect_many(features):
            key = (found.source_ip, found.destination_ip, int(found.feature.get("destination_port", 0)))
            last = self._recent_anomalies.get(key)
            if last is not None and now - last < self._cooldown_seconds:
                continue
            self._recent_anomalies[key] = now
            self._dispatch(found)

    def _check_exfiltration(self, features: list[TrafficFeature]) -> None:
        volume: defaultdict[tuple[str, str], int] = defaultdict(int)
        for feature in features:
            if (self._context.is_local(feature.source_ip) or is_private(feature.source_ip)) and is_public(feature.destination_ip):
                volume[(feature.source_ip, feature.destination_ip)] += feature.bytes_total
        threshold = self._settings.exfil_mb * 1_000_000
        now = time.monotonic()
        for (source, destination), size in volume.items():
            if size < threshold or self._exfil_cooldown.active((source, destination), now):
                continue
            self._exfil_cooldown.trip((source, destination), now)
            window = features[0]
            self._dispatch(alert(
                window.window_end, source, destination, risk="medium", category="exfiltration",
                rule_id="L4-EXFIL-VOLUME", mitre="T1048", layer="L4", score=0.7, blockable=False,
                description=(
                    f"Posible exfiltración de datos: {source} envió {size / 1_000_000:.0f} MB a {destination} en una "
                    f"ventana de {round((window.window_end - window.window_start).total_seconds())} s."
                ),
                bytes=size,
            ))
