from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# TCP flag bits, as returned by ``int(packet[TCP].flags)`` in scapy.
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

SEVERITIES = ("low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


@dataclass(frozen=True, slots=True)
class PacketObservation:
    """A TCP or UDP segment (layer 4) with the bytes needed for L7 checks."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    size: int
    tcp_flags: int = 0
    payload: bytes = b""
    source_mac: str = ""


@dataclass(frozen=True, slots=True)
class ArpObservation:
    timestamp: datetime
    operation: int  # 1 = who-has (request), 2 = is-at (reply)
    sender_ip: str
    sender_mac: str
    target_ip: str


@dataclass(frozen=True, slots=True)
class IcmpObservation:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    icmp_type: int
    code: int
    size: int
    version: int = 4
    source_mac: str = ""


@dataclass(frozen=True, slots=True)
class DnsObservation:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    query: str
    query_type: int
    is_response: bool
    rcode: int
    size: int


@dataclass(frozen=True, slots=True)
class FragmentObservation:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    offset: int
    more_fragments: bool
    payload_size: int
    protocol: int


Observation = PacketObservation | ArpObservation | IcmpObservation | DnsObservation | FragmentObservation


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

    def payload(self) -> dict[str, object]:
        return {
            **asdict(self),
            "kind": "anomaly",
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class DetectionAlert:
    timestamp: datetime
    source_ip: str
    destination_ip: str
    risk: str  # low | medium | high | critical
    description: str
    score: float
    feature: dict[str, object]
    category: str = "anomaly"
    rule_id: str = ""
    mitre: str = ""
    layer: str = ""
    sensor: str = "engine"
    # False when blocking the source is useless or harmful (spoofed sources,
    # L2 attacks, reflectors, internal clients that only need review).
    blockable: bool = True
    action: str = "alert"

    def payload(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "sourceIp": self.source_ip,
            "destinationIp": self.destination_ip,
            "risk": self.risk,
            "description": self.description[:500],
            "score": self.score,
            "feature": self.feature,
            "category": self.category,
            "ruleId": self.rule_id,
            "mitre": self.mitre,
            "layer": self.layer,
            "sensor": self.sensor,
            "action": self.action,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """A vulnerability or weak configuration, as opposed to an attack in progress."""

    key: str
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str
    source: str = "traffic"  # traffic | audit
    asset: str = ""
    mitre: str = ""

    def payload(self) -> dict[str, object]:
        return {
            "key": self.key[:200],
            "severity": self.severity,
            "category": self.category,
            "title": self.title[:200],
            "detail": self.detail[:1000],
            "recommendation": self.recommendation[:1000],
            "source": self.source,
            "asset": self.asset[:100],
            "mitre": self.mitre,
        }
