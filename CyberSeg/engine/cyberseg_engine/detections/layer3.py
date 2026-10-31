"""Layer 3 (network): ICMP abuse, spoofed sources and fragmentation attacks."""

from __future__ import annotations

import ipaddress

from cyberseg_engine.detections.base import Cooldown, LruTable, NetworkContext, SlidingCount, SlidingDistinct, alert, ip
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.models import DetectionAlert, FragmentObservation, IcmpObservation, Observation, PacketObservation

_ECHO_REQUEST = {4: 8, 6: 128}
_BOGON_SOURCES = tuple(ipaddress.ip_network(net) for net in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "::1/128"))


class IcmpDetector:
    def __init__(self, settings: DetectionSettings, context: NetworkContext) -> None:
        self._settings = settings
        self._context = context
        self._sweeps = LruTable(SlidingDistinct)
        self._floods = LruTable(lambda: SlidingCount(cap=settings.icmp_flood_pps * 10))
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, IcmpObservation):
            return []
        now = observation.timestamp.timestamp()
        source, destination = observation.source_ip, observation.destination_ip
        if observation.version == 4 and observation.icmp_type == 5 and not self._cooldown.active(("redirect", source), now):
            self._cooldown.trip(("redirect", source), now)
            return [alert(
                observation.timestamp, source, destination, risk="medium", category="network_interception",
                rule_id="L3-ICMP-REDIRECT", mitre="T1557", layer="L3", blockable=False,
                description=f"Redirección ICMP recibida desde {source}: puede desviar el tráfico de {destination} hacia un atacante.",
            )]
        if observation.icmp_type != _ECHO_REQUEST[observation.version]:
            return []
        alerts: list[DetectionAlert] = []
        if destination == "255.255.255.255" or destination.endswith(".255"):
            if not self._cooldown.active(("smurf", destination), now):
                self._cooldown.trip(("smurf", destination), now)
                alerts.append(alert(
                    observation.timestamp, source, destination, risk="medium", category="denial_of_service",
                    rule_id="L3-SMURF", mitre="T1498.002", layer="L3", blockable=False,
                    description=f"Posible ataque Smurf: ping a la dirección de difusión {destination} con origen {source} (probablemente falsificado).",
                ))
            return alerts
        if not self._context.is_local(source) and not self._cooldown.active(("sweep", source), now):
            tracker = self._sweeps.touch(source)
            hosts = tracker.add(now, destination, 60)
            if hosts >= self._settings.ping_sweep_hosts:
                self._cooldown.trip(("sweep", source), now)
                tracker.seen.clear()
                alerts.append(alert(
                    observation.timestamp, source, destination, risk="high", category="reconnaissance",
                    rule_id="L3-PING-SWEEP", mitre="T1018", layer="L3",
                    description=f"Barrido ICMP (ping sweep): {source} sondeó {hosts} equipos distintos en 60 s para descubrir la red.",
                    hosts=hosts,
                ))
        rate_window = 5
        count = self._floods.touch((source, destination)).add(now, rate_window)
        if count >= self._settings.icmp_flood_pps * rate_window and not self._cooldown.active(("flood", source, destination), now):
            self._cooldown.trip(("flood", source, destination), now)
            alerts.append(alert(
                observation.timestamp, source, destination, risk="high", category="denial_of_service",
                rule_id="L3-ICMP-FLOOD", mitre="T1498.001", layer="L3",
                description=f"Flood ICMP: {source} envió {count} pings a {destination} en {rate_window} s ({count // rate_window} por segundo).",
                packets=count,
            ))
        return alerts


class SpoofingDetector:
    """LAND attacks and packets whose source address cannot exist on the wire."""

    def __init__(self, settings: DetectionSettings) -> None:
        self._cooldown = Cooldown(settings.alert_cooldown_seconds * 6)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, (PacketObservation, IcmpObservation)):
            return []
        now = observation.timestamp.timestamp()
        source, destination = observation.source_ip, observation.destination_ip
        if source == destination and not self._cooldown.active(("land", source), now):
            self._cooldown.trip(("land", source), now)
            return [alert(
                observation.timestamp, source, destination, risk="high", category="spoofing", rule_id="L3-LAND",
                mitre="T1498", layer="L3", blockable=False,
                description=f"Ataque LAND: paquete con origen y destino {source} idénticos (IP falsificada para bloquear la pila TCP/IP).",
            )]
        parsed = ip(source)
        if parsed is None or not any(parsed in network for network in _BOGON_SOURCES if network.version == parsed.version):
            return []
        if isinstance(observation, PacketObservation) and (observation.source_port, observation.destination_port) == (68, 67):
            return []  # DHCP discover legitimately comes from 0.0.0.0
        if self._cooldown.active(("bogon", source), now):
            return []
        self._cooldown.trip(("bogon", source), now)
        return [alert(
            observation.timestamp, source, destination, risk="medium", category="spoofing", rule_id="L3-BOGON-SOURCE",
            mitre="T1498", layer="L3", blockable=False,
            description=f"IP de origen falsificada: llegó tráfico con origen {source}, una dirección que no puede existir en la red (bogon/martian).",
        )]


class FragmentDetector:
    def __init__(self, settings: DetectionSettings) -> None:
        self._settings = settings
        self._counts = LruTable(lambda: SlidingCount(cap=settings.fragment_flood * 2))
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, FragmentObservation):
            return []
        now = observation.timestamp.timestamp()
        source = observation.source_ip
        if (
            observation.offset == 0 and observation.more_fragments and observation.protocol == 6
            and observation.payload_size < self._settings.tiny_fragment_bytes
            and not self._cooldown.active(("tiny", source), now)
        ):
            self._cooldown.trip(("tiny", source), now)
            return [alert(
                observation.timestamp, source, observation.destination_ip, risk="high", category="evasion",
                rule_id="L3-TINY-FRAGMENT", mitre="", layer="L3",
                description=(
                    f"Fragmento diminuto desde {source}: el primer fragmento ({observation.payload_size} bytes) no "
                    f"contiene la cabecera TCP completa, técnica para evadir firewalls e IDS."
                ),
                payload_size=observation.payload_size,
            )]
        count = self._counts.touch(source).add(now, 10)
        if count >= self._settings.fragment_flood and not self._cooldown.active(("flood", source), now):
            self._cooldown.trip(("flood", source), now)
            return [alert(
                observation.timestamp, source, observation.destination_ip, risk="high", category="denial_of_service",
                rule_id="L3-FRAGMENT-FLOOD", mitre="T1498.001", layer="L3",
                description=f"Flood de fragmentos IP: {source} envió {count} fragmentos en 10 s (agotamiento del reensamblado, tipo teardrop).",
                fragments=count,
            )]
        return []
