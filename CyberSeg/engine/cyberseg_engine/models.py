from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class PacketObservation:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    size: int


@dataclass(frozen=True, slots=True)
class TrafficFeature:
    window_start: datetime
    window_end: datetime
    source_ip: str
    destination_ip: str
    destination_port: int
    packets: int
    bytes_total: int
    packets_per_second: float
    average_packet_size: float


@dataclass(frozen=True, slots=True)
class DetectionAlert:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    risk: str
    description: str
    score: float
    feature: TrafficFeature

    def payload(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "sourceIp": self.source_ip,
            "destinationIp": self.destination_ip,
            "risk": self.risk,
            "description": self.description,
            "score": self.score,
            "feature": {
                **asdict(self.feature),
                "window_start": self.feature.window_start.isoformat(),
                "window_end": self.feature.window_end.isoformat(),
            },
        }
