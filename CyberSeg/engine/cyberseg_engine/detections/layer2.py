"""Layer 2 (data link): man-in-the-middle and switch attacks on the local segment."""

from __future__ import annotations

from cyberseg_engine.detections.base import Cooldown, LruTable, NetworkContext, SlidingCount, SlidingDistinct, alert
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.models import ArpObservation, DetectionAlert, IcmpObservation, Observation, PacketObservation

_MAC_CHANGE_WINDOW_SECONDS = 1800


class ArpDetector:
    """ARP cache poisoning (MAC changes, reply floods) and ARP host discovery."""

    def __init__(self, settings: DetectionSettings, context: NetworkContext) -> None:
        self._settings = settings
        self._context = context
        self._ip_to_mac: LruTable = LruTable(dict)
        self._replies = LruTable(SlidingCount)
        self._sweeps = LruTable(SlidingDistinct)
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, ArpObservation) or observation.sender_ip in {"", "0.0.0.0"}:
            return []
        now = observation.timestamp.timestamp()
        alerts: list[DetectionAlert] = []
        sender_ip, sender_mac = observation.sender_ip, observation.sender_mac.lower()

        known = self._ip_to_mac.touch(sender_ip)
        previous = known.get("mac")
        gateway = sender_ip == self._context.gateway_ip
        # A device that left and whose IP was later reassigned (DHCP) is not an
        # attack; poisoning shows a new MAC while the old one is still active.
        # The gateway's MAC should never change, so it is always reported.
        recent = now - known.get("seen", now) <= _MAC_CHANGE_WINDOW_SECONDS
        if previous and previous != sender_mac and (gateway or recent) and not self._cooldown.active(("spoof", sender_ip), now):
            self._cooldown.trip(("spoof", sender_ip), now)
            alerts.append(alert(
                observation.timestamp, sender_ip, observation.target_ip,
                risk="critical" if gateway else "high", category="network_interception", rule_id="L2-ARP-SPOOF",
                mitre="T1557.002", layer="L2", score=0.95 if gateway else 0.85, blockable=False,
                description=(
                    f"Posible ARP spoofing (man in the middle): la IP {sender_ip}"
                    f"{' (puerta de enlace)' if gateway else ''} cambió de MAC {previous} a {sender_mac}."
                ),
                previous_mac=previous, new_mac=sender_mac, gateway=gateway,
            ))
        known["mac"], known["seen"] = sender_mac, now

        if observation.operation == 2:
            count = self._replies.touch(sender_mac).add(now, 10)
            if count >= self._settings.arp_reply_flood and not self._cooldown.active(("replies", sender_mac), now):
                self._cooldown.trip(("replies", sender_mac), now)
                alerts.append(alert(
                    observation.timestamp, sender_ip, observation.target_ip, risk="high",
                    category="network_interception", rule_id="L2-ARP-POISON", mitre="T1557.002", layer="L2",
                    blockable=False,
                    description=(
                        f"Envenenamiento ARP activo: la MAC {sender_mac} envió {count} respuestas ARP no "
                        f"solicitadas en 10 s (herramientas tipo arpspoof/bettercap)."
                    ),
                    mac=sender_mac, replies=count,
                ))
        elif observation.operation == 1 and sender_ip != self._context.gateway_ip and not self._context.is_local(sender_ip):
            tracker = self._sweeps.touch(sender_mac)
            hosts = tracker.add(now, observation.target_ip, 60)
            if hosts >= self._settings.arp_sweep_hosts and not self._cooldown.active(("sweep", sender_mac), now):
                self._cooldown.trip(("sweep", sender_mac), now)
                tracker.seen.clear()
                alerts.append(alert(
                    observation.timestamp, sender_ip, observation.target_ip, risk="medium",
                    category="reconnaissance", rule_id="L2-ARP-SWEEP", mitre="T1018", layer="L2", blockable=False,
                    description=f"Descubrimiento de equipos por ARP: {sender_ip} ({sender_mac}) preguntó por {hosts} IPs en 60 s.",
                    mac=sender_mac, hosts=hosts,
                ))
        return alerts


class MacFloodDetector:
    """CAM table overflow: thousands of new source MACs in a few seconds (macof)."""

    def __init__(self, settings: DetectionSettings) -> None:
        self._settings = settings
        self._macs = SlidingDistinct()
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        mac = getattr(observation, "source_mac", "") or getattr(observation, "sender_mac", "")
        if not mac:
            return []
        now = observation.timestamp.timestamp()
        if self._cooldown.active(("flood",), now):
            return []
        count = self._macs.add(now, mac, 10)
        if count < self._settings.mac_flood_macs:
            return []
        self._cooldown.trip(("flood",), now)
        self._macs.seen.clear()
        source = getattr(observation, "source_ip", "") or getattr(observation, "sender_ip", "")
        return [alert(
            observation.timestamp, source, getattr(observation, "destination_ip", ""), risk="high",
            category="network_interception", rule_id="L2-MAC-FLOOD", mitre="T1557", layer="L2", blockable=False,
            description=(
                f"Inundación de direcciones MAC: {count} MACs de origen distintas en 10 s. Un atacante intenta "
                f"desbordar la tabla CAM del switch para espiar el tráfico (macof)."
            ),
            distinct_macs=count,
        )]


class RogueServiceDetector:
    """Unauthorised DHCP servers and IPv6 router advertisements (MITM via config)."""

    def __init__(self, settings: DetectionSettings, dhcp_servers: tuple[str, ...] = ()) -> None:
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)
        self._dhcp = set(dhcp_servers)
        self._learn_dhcp = not dhcp_servers
        self._routers: set[str] = set()

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        now = observation.timestamp.timestamp()
        if isinstance(observation, PacketObservation) and observation.protocol == "udp" and (
            observation.source_port, observation.destination_port
        ) == (67, 68):
            server = observation.source_ip
            if self._learn_dhcp and not self._dhcp:
                self._dhcp.add(server)
            if server in self._dhcp or self._cooldown.active(("dhcp", server), now):
                return []
            self._cooldown.trip(("dhcp", server), now)
            return [alert(
                observation.timestamp, server, observation.destination_ip, risk="critical",
                category="network_interception", rule_id="L2-ROGUE-DHCP", mitre="T1557.003", layer="L2",
                score=0.9, blockable=False,
                description=(
                    f"Servidor DHCP no autorizado: {server} está repartiendo configuración de red "
                    f"(autorizados: {', '.join(sorted(self._dhcp))}). Puede desviar el tráfico a un atacante."
                ),
                authorized=sorted(self._dhcp),
            )]
        if isinstance(observation, IcmpObservation) and observation.version == 6 and observation.icmp_type == 134:
            router = observation.source_ip
            if not self._routers:
                self._routers.add(router)
            if router in self._routers or self._cooldown.active(("ra", router), now):
                return []
            self._cooldown.trip(("ra", router), now)
            return [alert(
                observation.timestamp, router, observation.destination_ip, risk="high",
                category="network_interception", rule_id="L2-ROGUE-RA", mitre="T1557", layer="L2", blockable=False,
                description=(
                    f"Router Advertisement IPv6 no autorizado desde {router}: un equipo se anuncia como router "
                    f"(posible man in the middle por IPv6)."
                ),
                known_routers=sorted(self._routers),
            )]
        return []
