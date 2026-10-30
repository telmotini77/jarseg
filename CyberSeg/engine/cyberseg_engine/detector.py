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

    def train(self, baseline: list[TrafficFeature]) -> None:
        if len(baseline) < 8:
            raise ValueError("Se requieren al menos ocho segmentos normales para entrenar el modelo.")
        self._model = IsolationForest(contamination=self.contamination, random_state=42, n_estimators=150)
        self._model.fit([_vector(item) for item in baseline])

    def detect(self, feature: TrafficFeature) -> DetectionAlert | None:
        if self._model is None:
            return None
        score = float(-self._model.score_samples([_vector(feature)])[0])
        suspicious = int(self._model.predict([_vector(feature)])[0]) == -1
        if not suspicious:
            return None
        risk = "high" if score >= 0.62 else "medium"
        return DetectionAlert(
            timestamp=datetime.now(timezone.utc), source_ip=feature.source_ip, destination_ip=feature.destination_ip,
            risk=risk, score=score,
            description=f"Patrón anómalo local: {feature.packets} paquetes hacia el puerto {feature.destination_port}.",
            feature=feature,
        )
