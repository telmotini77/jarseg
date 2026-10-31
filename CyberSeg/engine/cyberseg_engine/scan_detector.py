"""Deterministic detection of port scans and network sweeps.

Unlike the Isolation Forest, these rules need no learned baseline and work from
the first captured packet. They count the distinct ports (or hosts) that one
source probes inside a sliding window, the same signal used by classic IDS
port-scan preprocessors, and flag TCP probes that no real connection sends.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass

from cyberseg_engine.detections.base import SlidingDistinct

from cyberseg_engine.models import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCP_URG, DetectionAlert, PacketObservation

# Ports that ordinary clients open towards many different hosts (DNS, web,
# NTP). A "sweep" on them is everyday browsing, so horizontal scans ignore them.
_CLIENT_PORTS = frozenset({53, 80, 123, 443, 853})

_LABELS = {"syn": "SYN", "udp": "UDP", "null": "NULL", "fin": "FIN", "xmas": "XMAS", "invalid": "con flags inválidos"}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class ScanThresholds:
    window_seconds: int = 60
    distinct_ports: int = 15
    distinct_hosts: int = 20
    stealth_ports: int = 3
    cooldown_seconds: int = 600
    max_tracked: int = 20_000


def probe_technique(packet: PacketObservation) -> str | None:
    """Return the probe technique a packet represents, or None for normal traffic."""
    if packet.protocol == "tcp":
        flags = packet.tcp_flags
        if flags & TCP_SYN and not flags & (TCP_ACK | TCP_RST):
            return "syn"
        if flags & (TCP_SYN | TCP_ACK | TCP_RST):
            return None
        # Every segment of a real TCP connection carries SYN, ACK or RST.
        # Segments without any of them are stealth probes (nmap -sN/-sF/-sX).
        if flags & 0x3F == 0:
            return "null"
        if flags & 0x3F == TCP_FIN:
            return "fin"
        if flags & (TCP_FIN | TCP_PSH | TCP_URG) == TCP_FIN | TCP_PSH | TCP_URG:
            return "xmas"
        return "invalid"
    if packet.protocol == "udp" and packet.source_port >= 1024 and packet.destination_port < 32768:
        # Answers from services (source port < 1024) and datagrams towards the
        # ephemeral range are replies to our own requests, not probes.
        return "udp"
    return None


class PortScanDetector:
    def __init__(
        self,
        thresholds: ScanThresholds | None = None,
        *,
        allowlist: tuple[str, ...] = (),
        local_addresses: frozenset[str] = frozenset(),
    ) -> None:
        self.thresholds = thresholds or ScanThresholds()
        self._allowlist: tuple[Network, ...] = tuple(ipaddress.ip_network(item, strict=False) for item in allowlist)
        self._local = local_addresses
        self._vertical: OrderedDict[tuple[str, str, str], SlidingDistinct] = OrderedDict()
        self._stealth: OrderedDict[tuple[str, str], SlidingDistinct] = OrderedDict()
        self._horizontal: OrderedDict[tuple[str, int, str], SlidingDistinct] = OrderedDict()
        # Cooldown is per source and scan type so a /24 sweep or a long scan
        # produces one actionable alert, not one per host or per port.
        self._cooldown: OrderedDict[tuple[str, ...], float] = OrderedDict()
        self._ignored: dict[str, bool] = {}

    def observe(self, packet: PacketObservation) -> list[DetectionAlert]:
        if not isinstance(packet, PacketObservation):
            return []
        technique = probe_technique(packet)
        if technique is None or self._is_ignored(packet):
            return []
        now = packet.timestamp.timestamp()
        window = float(self.thresholds.window_seconds)
        source, destination, port = packet.source_ip, packet.destination_ip, packet.destination_port
        alerts: list[DetectionAlert] = []

        if technique in {"null", "fin", "xmas", "invalid"}:
            cooldown_key = ("stealth", source)
            if not self._cooling_down(cooldown_key, now):
                tracker = self._tracker(self._stealth, (source, destination))
                tracker.labels.add(technique)
                if tracker.add(now, port, window) >= self.thresholds.stealth_ports:
                    alerts.append(self._stealth_alert(packet, tracker, now))
                    self._trip(self._stealth, (source, destination), cooldown_key, now)
            return alerts

        protocol = packet.protocol
        cooldown_key = ("vertical", source, protocol)
        if not self._cooling_down(cooldown_key, now):
            tracker = self._tracker(self._vertical, (source, destination, protocol))
            tracker.labels.add(technique)
            if tracker.add(now, port, window) >= self.thresholds.distinct_ports:
                alerts.append(self._vertical_alert(packet, tracker, now))
                self._trip(self._vertical, (source, destination, protocol), cooldown_key, now)

        # Outbound connections from this server to many hosts are normal
        # client behaviour; only foreign sources are checked for sweeps.
        if port not in _CLIENT_PORTS and source not in self._local:
            cooldown_key = ("horizontal", source, protocol)
            if not self._cooling_down(cooldown_key, now):
                tracker = self._tracker(self._horizontal, (source, port, protocol))
                tracker.labels.add(technique)
                if tracker.add(now, destination, window) >= self.thresholds.distinct_hosts:
                    alerts.append(self._horizontal_alert(packet, tracker, now))
                    self._trip(self._horizontal, (source, port, protocol), cooldown_key, now)
        return alerts

    def _vertical_alert(self, packet: PacketObservation, tracker: SlidingDistinct, now: float) -> DetectionAlert:
        ports = sorted(int(port) for port in tracker.seen)
        label = _LABELS["udp" if packet.protocol == "udp" else "syn"]
        span = tracker.span(now)
        return self._alert(
            packet, score=0.85,
            description=(
                f"Escaneo de puertos {label} detectado: {packet.source_ip} sondeó {len(ports)} puertos "
                f"{packet.protocol.upper()} distintos de {packet.destination_ip} en {span}s "
                f"(p. ej. {_preview(ports)})."
            ),
            details={"scan_type": "vertical", "technique": label.lower(), "distinct_ports": len(ports), "ports_sample": ports[:20], "observed_seconds": span},
        )

    def _stealth_alert(self, packet: PacketObservation, tracker: SlidingDistinct, now: float) -> DetectionAlert:
        ports = sorted(int(port) for port in tracker.seen)
        labels = "/".join(_LABELS[item] for item in sorted(tracker.labels))
        return self._alert(
            packet, score=0.95,
            description=(
                f"Escaneo de puertos sigiloso {labels} detectado: {packet.source_ip} envió sondas TCP sin "
                f"SYN/ACK/RST a {len(ports)} puertos de {packet.destination_ip} (p. ej. {_preview(ports)})."
            ),
            details={"scan_type": "stealth", "technique": labels.lower(), "distinct_ports": len(ports), "ports_sample": ports[:20], "observed_seconds": tracker.span(now)},
        )

    def _horizontal_alert(self, packet: PacketObservation, tracker: SlidingDistinct, now: float) -> DetectionAlert:
        hosts = len(tracker.seen)
        span = tracker.span(now)
        return self._alert(
            packet, score=0.85,
            description=(
                f"Barrido de red (escaneo horizontal) detectado: {packet.source_ip} sondeó el puerto "
                f"{packet.destination_port}/{packet.protocol.upper()} en {hosts} equipos distintos en {span}s."
            ),
            details={"scan_type": "horizontal", "technique": "sweep", "distinct_hosts": hosts, "destination_port": packet.destination_port, "observed_seconds": span},
        )

    def _alert(self, packet: PacketObservation, *, score: float, description: str, details: dict[str, object]) -> DetectionAlert:
        rule = {"vertical": "L4-PORTSCAN", "stealth": "L4-PORTSCAN-STEALTH", "horizontal": "L4-NETWORK-SWEEP"}[str(details["scan_type"])]
        return DetectionAlert(
            timestamp=packet.timestamp, source_ip=packet.source_ip, destination_ip=packet.destination_ip,
            risk="high", score=score, description=description, category="reconnaissance", rule_id=rule,
            mitre="T1046", layer="L4",
            feature={
                "kind": "port_scan", "protocol": packet.protocol, "source_ip": packet.source_ip,
                "destination_ip": packet.destination_ip, "window_seconds": self.thresholds.window_seconds, **details,
            },
        )

    def _tracker(self, table: OrderedDict, key: tuple) -> SlidingDistinct:
        tracker = table.get(key)
        if tracker is None:
            tracker = table[key] = SlidingDistinct()
            if len(table) > self.thresholds.max_tracked:
                table.popitem(last=False)
        else:
            table.move_to_end(key)
        return tracker

    def _trip(self, table: OrderedDict, key: tuple, cooldown_key: tuple[str, ...], now: float) -> None:
        table.pop(key, None)
        self._cooldown[cooldown_key] = now + self.thresholds.cooldown_seconds
        self._cooldown.move_to_end(cooldown_key)
        if len(self._cooldown) > self.thresholds.max_tracked:
            self._cooldown.popitem(last=False)

    def _cooling_down(self, key: tuple[str, ...], now: float) -> bool:
        until = self._cooldown.get(key)
        if until is None:
            return False
        if until > now:
            return True
        del self._cooldown[key]
        return False

    def _is_ignored(self, packet: PacketObservation) -> bool:
        source = packet.source_ip
        ignored = self._ignored.get(source)
        if ignored is None:
            try:
                address = ipaddress.ip_address(source)
                ignored = address.is_loopback or any(address in network for network in self._allowlist)
            except ValueError:
                ignored = True
            if len(self._ignored) > self.thresholds.max_tracked:
                self._ignored.clear()
            self._ignored[source] = ignored
        if ignored:
            return True
        try:
            # Multicast/broadcast discovery (mDNS, SSDP, NetBIOS) is not a scan.
            destination = ipaddress.ip_address(packet.destination_ip)
        except ValueError:
            return True
        return destination.is_multicast or destination == ipaddress.IPv4Address("255.255.255.255")


def _preview(ports: list[int], limit: int = 8) -> str:
    shown = ", ".join(str(port) for port in ports[:limit])
    return shown + ("…" if len(ports) > limit else "")
