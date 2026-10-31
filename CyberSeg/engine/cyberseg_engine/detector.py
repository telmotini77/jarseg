from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sklearn.ensemble import IsolationForest

from cyberseg_engine.models import DetectionAlert, TrafficFeature


def _vector(feature: TrafficFeature) -> list[float]:
    return [float(feature.packets), float(feature.bytes_total), feature.packets_per_second, feature.average_packet_size]


@dataclass(slots=True)
class AnomalyDetector:
    contamination: float = 0.02
    _model: IsolationForest | None = None

    @property
    def trained(self) -> bool:
        return self._model is not None

    def train(self, baseline: list[TrafficFeature]) -> None:
        if len(baseline) < 8:
            raise ValueError("Se requieren al menos ocho segmentos normales para entrenar el modelo.")
        self._model = IsolationForest(contamination=self.contamination, random_state=42, n_estimators=150)
        self._model.fit([_vector(item) for item in baseline])

    def detect(self, feature: TrafficFeature) -> DetectionAlert | None:
        alerts = self.detect_many([feature])
        return alerts[0] if alerts else None

    def detect_many(self, features: list[TrafficFeature]) -> list[DetectionAlert]:
        # One vectorised call per window: scoring flows one by one is orders of
        # magnitude slower on a busy server.
        if self._model is None or not features:
            return []
        vectors = [_vector(item) for item in features]
        scores = -self._model.score_samples(vectors)
        labels = self._model.predict(vectors)
        alerts = []
        for feature, score, label in zip(features, scores, labels):
            if int(label) != -1:
                continue
            alerts.append(DetectionAlert(
                timestamp=datetime.now(timezone.utc), source_ip=feature.source_ip, destination_ip=feature.destination_ip,
                risk="high" if score >= 0.62 else "medium", score=float(score),
                description=f"Patrón anómalo local: {feature.packets} paquetes hacia el puerto {feature.destination_port}.",
                feature=feature.payload(), category="anomaly", rule_id="ML-ISOLATION-FOREST", layer="L4",
                # Statistical outliers are leads for review, never a reason to block.
                blockable=False,
            ))
        return alerts
