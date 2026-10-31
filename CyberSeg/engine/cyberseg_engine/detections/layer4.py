"""Layer 4 (transport): volumetric floods and reflection/amplification DDoS."""

from __future__ import annotations

from cyberseg_engine.detections.base import Cooldown, LruTable, NetworkContext, TumblingWindow, alert
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.models import TCP_ACK, TCP_RST, TCP_SYN, DetectionAlert, Observation, PacketObservation

# UDP services abused as reflectors, with their usual amplification name.
_REFLECTORS = {
    53: "DNS", 123: "NTP", 19: "CharGEN", 1900: "SSDP", 11211: "memcached", 389: "CLDAP",
    161: "SNMP", 137: "NetBIOS", 5353: "mDNS", 3702: "WS-Discovery", 3283: "ARD",
}
_CLIENT_UDP_SOURCES = frozenset({53, 123, 443})


class FloodDetector:
    def __init__(self, settings: DetectionSettings, context: NetworkContext) -> None:
        self._settings = settings
        self._context = context
        self._syn = LruTable(TumblingWindow)
        self._udp = LruTable(TumblingWindow)
        self._reflection = LruTable(TumblingWindow)
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, PacketObservation):
            return []
        if observation.protocol == "tcp":
            return self._syn_flood(observation)
        if observation.protocol == "udp":
            return self._udp_flood(observation)
        return []

    def _syn_flood(self, packet: PacketObservation) -> list[DetectionAlert]:
        flags = packet.tcp_flags
        if not flags & TCP_SYN or flags & (TCP_ACK | TCP_RST):
            return []
        now = packet.timestamp.timestamp()
        window = self._settings.flood_window_seconds
        target = (packet.destination_ip, packet.destination_port)
        bucket = self._syn.touch(target)
        bucket.add(now, window, packet.source_ip)
        if bucket.total < self._settings.syn_flood_pps * window or self._cooldown.active(("syn", *target), now):
            return []
        self._cooldown.trip(("syn", *target), now)
        return [self._flood_alert(packet, bucket, "TCP SYN", "L4-SYN-FLOOD", window)]

    def _udp_flood(self, packet: PacketObservation) -> list[DetectionAlert]:
        now = packet.timestamp.timestamp()
        window = self._settings.flood_window_seconds
        service = _REFLECTORS.get(packet.source_port)
        if service and packet.size >= self._settings.reflection_min_bytes and self._context.is_local(packet.destination_ip):
            bucket = self._reflection.touch(packet.destination_ip)
            bucket.add(now, window, packet.source_ip)
            if bucket.total >= self._settings.reflection_pps * window and not self._cooldown.active(("reflection", packet.destination_ip), now):
                self._cooldown.trip(("reflection", packet.destination_ip), now)
                return [alert(
                    packet.timestamp, bucket.by_key.most_common(1)[0][0], packet.destination_ip, risk="critical",
                    category="denial_of_service", rule_id="L4-REFLECTION-DDOS", mitre="T1498.002", layer="L4",
                    score=0.95, blockable=False,
                    description=(
                        f"DDoS por reflexión/amplificación {service}: {packet.destination_ip} recibió {bucket.total} "
                        f"respuestas grandes en {window} s desde {len(bucket.by_key)} servidores reflectores. "
                        f"Mitígalo con tu proveedor (filtrado aguas arriba)."
                    ),
                    service=service, packets=bucket.total, reflectors=len(bucket.by_key),
                )]
            return []
        if (
            packet.destination_port >= 32768 or packet.source_port in _CLIENT_UDP_SOURCES
            or not self._context.is_local(packet.destination_ip)
        ):
            return []
        key = (packet.source_ip, packet.destination_ip)
        bucket = self._udp.touch(key)
        bucket.add(now, window)
        if bucket.total < self._settings.udp_flood_pps * window or self._cooldown.active(("udp", *key), now):
            return []
        self._cooldown.trip(("udp", *key), now)
        return [alert(
            packet.timestamp, packet.source_ip, packet.destination_ip, risk="high", category="denial_of_service",
            rule_id="L4-UDP-FLOOD", mitre="T1498.001", layer="L4",
            description=f"Flood UDP: {packet.source_ip} envió {bucket.total} datagramas a {packet.destination_ip} en {window} s.",
            packets=bucket.total,
        )]

    @staticmethod
    def _flood_alert(packet: PacketObservation, bucket: TumblingWindow, kind: str, rule: str, window: int) -> DetectionAlert:
        top_source, top_count = bucket.by_key.most_common(1)[0]
        sources = len(bucket.by_key)
        # One dominant source can be blocked; thousands of (spoofed) sources
        # mean a DDoS that must be absorbed upstream or with SYN cookies.
        single = top_count / bucket.total >= 0.8
        target = f"{packet.destination_ip}:{packet.destination_port}"
        description = (
            f"{kind} flood contra {target}: {bucket.total} intentos en {window} s desde {top_source}."
            if single else
            f"{kind} flood distribuido (DDoS) contra {target}: {bucket.total} intentos en {window} s desde "
            f"{sources} orígenes, probablemente falsificados."
        )
        return alert(
            packet.timestamp, top_source, packet.destination_ip, risk="high" if single else "critical",
            category="denial_of_service", rule_id=rule, mitre="T1498.001", layer="L4", blockable=single,
            score=0.9, description=description, packets=bucket.total, sources=sources,
            destination_port=packet.destination_port,
        )
