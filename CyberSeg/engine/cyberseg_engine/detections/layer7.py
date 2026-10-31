"""Layer 7 and behavioural detections: credential attacks, C2, DNS abuse,
lateral movement, and insecure protocols that expose the network.

Payload checks only read the first bytes of unencrypted protocols; exploit
signatures for application traffic are Suricata's job (see suricata.py).
"""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter, deque

from cyberseg_engine.detections.base import (
    Cooldown, LruTable, NetworkContext, SlidingCount, SlidingDistinct, alert, is_private, is_public,
)
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.models import (
    TCP_ACK, TCP_RST, TCP_SYN, DetectionAlert, DnsObservation, Finding, Observation, PacketObservation,
)

AUTH_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 27017: "MongoDB",
}
ADMIN_PORTS = frozenset({22, 135, 139, 445, 3389, 5900, 5985, 5986})
_HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8888})
_HTTP_STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")


def is_new_connection(packet: PacketObservation) -> bool:
    return packet.protocol == "tcp" and bool(packet.tcp_flags & TCP_SYN) and not packet.tcp_flags & (TCP_ACK | TCP_RST)


class BruteForceDetector:
    """Connection-rate brute force: works even when the protocol is encrypted."""

    def __init__(self, settings: DetectionSettings) -> None:
        self._settings = settings
        self._attempts = LruTable(lambda: SlidingCount(cap=settings.bruteforce_attempts * 4))
        self._not_found = LruTable(SlidingCount)
        self._cooldown = Cooldown(settings.alert_cooldown_seconds)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, PacketObservation):
            return []
        if observation.source_port in _HTTP_PORTS and observation.payload.startswith(b"HTTP/1."):
            return self._web_discovery(observation)
        service = AUTH_SERVICES.get(observation.destination_port)
        if service is None or not is_new_connection(observation):
            return []
        now = observation.timestamp.timestamp()
        key = (observation.source_ip, observation.destination_ip, observation.destination_port)
        window = self._settings.bruteforce_window_seconds
        count = self._attempts.touch(key).add(now, window)
        if count < self._settings.bruteforce_attempts or self._cooldown.active(("brute", observation.source_ip, service), now):
            return []
        self._cooldown.trip(("brute", observation.source_ip, service), now)
        return [alert(
            observation.timestamp, observation.source_ip, observation.destination_ip, risk="high",
            category="credential_access", rule_id=f"L7-BRUTEFORCE-{service.upper()}", mitre="T1110", layer="L7",
            description=(
                f"Fuerza bruta contra {service} ({observation.destination_ip}:{observation.destination_port}): "
                f"{observation.source_ip} abrió {count} conexiones en {window} s probando credenciales."
            ),
            service=service, attempts=count, destination_port=observation.destination_port,
        )]

    def _web_discovery(self, response: PacketObservation) -> list[DetectionAlert]:
        match = _HTTP_STATUS.match(response.payload)
        if match is None or match.group(1) != b"404":
            return []
        now = response.timestamp.timestamp()
        client, server = response.destination_ip, response.source_ip
        count = self._not_found.touch((client, server)).add(now, 60)
        if count < self._settings.web_404_responses or self._cooldown.active(("web", client), now):
            return []
        self._cooldown.trip(("web", client), now)
        return [alert(
            response.timestamp, client, server, risk="high", category="reconnaissance",
            rule_id="L7-WEB-DISCOVERY", mitre="T1595.003", layer="L7",
            description=(
                f"Escaneo de contenido web: {client} provocó {count} respuestas 404 en {server}:{response.source_port} "
                f"en 60 s (fuerza bruta de rutas tipo dirb/gobuster)."
            ),
            not_found=count,
        )]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(count / len(text) * math.log2(count / len(text)) for count in counts.values())


def _base_domain(name: str) -> str:
    labels = [label for label in name.rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


class DnsThreatDetector:
    """DNS tunnelling/exfiltration and DGA-style NXDOMAIN storms."""

    def __init__(self, settings: DetectionSettings) -> None:
        self._settings = settings
        self._subdomains = LruTable(SlidingDistinct)
        self._nxdomain = LruTable(SlidingCount)
        self._cooldown = Cooldown(settings.alert_cooldown_seconds * 3)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, DnsObservation) or not observation.query:
            return []
        now = observation.timestamp.timestamp()
        if observation.is_response:
            if observation.rcode != 3:
                return []
            client = observation.destination_ip
            count = self._nxdomain.touch(client).add(now, 60)
            if count < self._settings.dns_nxdomain or self._cooldown.active(("nx", client), now):
                return []
            self._cooldown.trip(("nx", client), now)
            return [alert(
                observation.timestamp, client, observation.source_ip, risk="medium", category="command_control",
                rule_id="L7-DNS-NXDOMAIN", mitre="T1568.002", layer="L7", blockable=False,
                description=(
                    f"Posible malware con DGA: {client} recibió {count} respuestas NXDOMAIN en 60 s "
                    f"(dominios inexistentes generados para localizar su servidor de control)."
                ),
                nxdomain=count,
            )]

        client, name = observation.source_ip, observation.query.rstrip(".").lower()
        base = _base_domain(name)
        subdomain = name[: -len(base)].rstrip(".") if name.endswith(base) else ""
        longest = max((len(label) for label in subdomain.split(".")), default=0) if subdomain else 0
        unique = self._subdomains.touch((client, base)).add(now, subdomain or name, 60)
        suspicious_label = longest >= self._settings.dns_long_label and _entropy(subdomain.replace(".", "")) >= 3.5
        # A single long random label is common (CDN tokens, AV lookups); a
        # stream of them towards one domain is how DNS tunnels carry data.
        if suspicious_label and unique >= max(5, self._settings.dns_unique_subdomains // 5):
            risk = "high"
        elif unique >= self._settings.dns_unique_subdomains:
            risk = "medium"
        else:
            return []
        if self._cooldown.active(("tunnel", client, base), now):
            return []
        self._cooldown.trip(("tunnel", client, base), now)
        return [alert(
            observation.timestamp, client, observation.destination_ip, risk=risk,
            category="exfiltration", rule_id="L7-DNS-TUNNEL", mitre="T1071.004", layer="L7", blockable=False,
            description=(
                f"Posible túnel DNS / exfiltración por DNS: {client} consultó {unique} subdominios distintos de "
                f"{base} en 60 s{f' con etiquetas de {longest} caracteres de alta entropía' if suspicious_label else ''}."
            ),
            domain=base, unique_subdomains=unique, longest_label=longest,
        )]


class BeaconDetector:
    """Periodic connections from an internal host to the same external server (C2)."""

    def __init__(self, settings: DetectionSettings) -> None:
        self._settings = settings
        self._history = LruTable(lambda: deque(maxlen=max(12, settings.beacon_min_connections + 2)))
        self._cooldown = Cooldown(6 * 3600)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, PacketObservation) or not is_new_connection(observation):
            return []
        if not is_private(observation.source_ip) or not is_public(observation.destination_ip):
            return []
        now = observation.timestamp.timestamp()
        key = (observation.source_ip, observation.destination_ip, observation.destination_port)
        history = self._history.touch(key)
        if history and now - history[-1] < 1:
            return []  # retransmission or parallel connections, not a new beacon
        history.append(now)
        if len(history) < self._settings.beacon_min_connections or self._cooldown.active(key, now):
            return []
        intervals = [later - earlier for earlier, later in zip(history, list(history)[1:])]
        mean = statistics.fmean(intervals)
        if not 10 <= mean <= 3600:
            return []
        jitter = statistics.pstdev(intervals) / mean
        if jitter > self._settings.beacon_max_jitter:
            return []
        self._cooldown.trip(key, now)
        return [alert(
            observation.timestamp, observation.source_ip, observation.destination_ip, risk="medium",
            category="command_control", rule_id="L7-BEACONING", mitre="T1071", layer="L7", score=0.7,
            blockable=False,
            description=(
                f"Posible beaconing C2: {observation.source_ip} contacta {observation.destination_ip}:"
                f"{observation.destination_port} cada {mean:.0f} s con una regularidad del {100 - jitter * 100:.0f} %. "
                f"Verifica qué proceso lo genera."
            ),
            interval_seconds=round(mean, 1), jitter=round(jitter, 3), connections=len(history),
            destination_port=observation.destination_port,
        )]


class LateralMovementDetector:
    """An internal host opening admin protocols (SMB, RDP, WinRM, SSH) on many peers."""

    def __init__(self, settings: DetectionSettings, context: NetworkContext) -> None:
        self._settings = settings
        self._context = context
        self._targets = LruTable(SlidingDistinct)
        self._cooldown = Cooldown(settings.alert_cooldown_seconds * 3)

    def observe(self, observation: Observation) -> list[DetectionAlert]:
        if not isinstance(observation, PacketObservation) or observation.destination_port not in ADMIN_PORTS:
            return []
        if not is_new_connection(observation) or not (is_private(observation.source_ip) and is_private(observation.destination_ip)):
            return []
        source = observation.source_ip
        now = observation.timestamp.timestamp()
        if self._cooldown.active(("lateral", source), now):
            return []
        tracker = self._targets.touch(source)
        tracker.labels.add(str(observation.destination_port))
        hosts = tracker.add(now, observation.destination_ip, self._settings.lateral_window_seconds)
        if hosts < self._settings.lateral_hosts:
            return []
        self._cooldown.trip(("lateral", source), now)
        ports = ", ".join(sorted(tracker.labels, key=int))
        local = self._context.is_local(source)
        tracker.seen.clear()
        return [alert(
            observation.timestamp, source, observation.destination_ip, risk="high" if local else "medium",
            category="lateral_movement", rule_id="L7-LATERAL-MOVEMENT", mitre="T1021", layer="L7", blockable=False,
            description=(
                f"Posible movimiento lateral: {source}{' (este servidor)' if local else ''} abrió servicios de "
                f"administración remota (puertos {ports}) en {hosts} equipos internos en "
                f"{self._settings.lateral_window_seconds // 60} min."
            ),
            hosts=hosts, ports=ports,
        )]


class InsecureProtocolDetector:
    """Report cleartext or obsolete protocols seen on the wire as vulnerabilities.

    Credentials are never stored: only the fact that they travelled unencrypted.
    """

    def __init__(self) -> None:
        self._reported: set[str] = set()

    def observe(self, observation: Observation) -> list[Finding]:
        if not isinstance(observation, PacketObservation) or not observation.payload:
            return []
        finding = self._classify(observation)
        if finding is None or finding.key in self._reported:
            return []
        if len(self._reported) > 50_000:
            self._reported.clear()
        self._reported.add(finding.key)
        return [finding]

    def _classify(self, packet: PacketObservation) -> Finding | None:
        data, sport, dport = packet.payload, packet.source_port, packet.destination_port
        server = f"{packet.destination_ip}:{dport}"
        if packet.protocol == "tcp":
            if 23 in (sport, dport):
                host = f"{packet.source_ip}:23" if sport == 23 else server
                return Finding(
                    f"insecure:telnet:{host}", "high", "insecure_protocol", "Telnet en uso",
                    f"Se observó una sesión Telnet con {host}: usuario, contraseña y comandos viajan sin cifrar.",
                    "Desactiva Telnet y usa SSH.", asset=host, mitre="T1040",
                )
            if dport == 21 and data[:5] in (b"USER ", b"PASS "):
                return Finding(
                    f"insecure:ftp:{server}", "high", "insecure_protocol", "Credenciales FTP sin cifrar",
                    f"{packet.source_ip} envió credenciales FTP en texto claro a {server}.",
                    "Sustituye FTP por SFTP o FTPS y cambia las contraseñas expuestas.", asset=server, mitre="T1040",
                )
            if dport in (110, 143) and (data[:5] == b"PASS " or b" LOGIN " in data[:64]):
                name = "POP3" if dport == 110 else "IMAP"
                return Finding(
                    f"insecure:{name.lower()}:{server}", "medium", "insecure_protocol", f"Credenciales {name} sin cifrar",
                    f"{packet.source_ip} inició sesión en {name} sin TLS contra {server}.",
                    f"Exige {name} sobre TLS (puertos 995/993) o STARTTLS obligatorio.", asset=server, mitre="T1040",
                )
            if b"\r\nAuthorization: Basic " in data[:2048] and data[:8].split(b" ")[0].isalpha():
                return Finding(
                    f"insecure:http-basic:{server}", "high", "insecure_protocol", "Autenticación HTTP Basic sin cifrar",
                    f"{packet.source_ip} envió usuario y contraseña en HTTP sin TLS a {server}.",
                    "Publica el servicio solo por HTTPS y cambia las credenciales.", asset=server, mitre="T1040",
                )
            if sport == 445 and len(data) > 8 and data[4:8] == b"\xffSMB":
                host = f"{packet.source_ip}:445"
                return Finding(
                    f"insecure:smbv1:{host}", "critical", "insecure_protocol", "SMBv1 habilitado",
                    f"El servidor {host} respondió con SMBv1, el protocolo explotado por EternalBlue/WannaCry.",
                    "Deshabilita SMBv1 (Windows: Disable-WindowsOptionalFeature SMB1Protocol; Samba: server min protocol = SMB2).",
                    asset=host, mitre="T1210",
                )
            if len(data) > 10 and data[0] == 0x16 and data[5] == 0x02:
                version = int.from_bytes(data[9:11], "big")
                names = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}
                if version in names:
                    host = f"{packet.source_ip}:{sport}"
                    return Finding(
                        f"insecure:tls:{host}", "high", "insecure_protocol", f"{names[version]} negociado",
                        f"El servidor {host} aceptó {names[version]}, vulnerable a ataques de degradación (POODLE, BEAST).",
                        "Configura el servidor para aceptar solo TLS 1.2 y TLS 1.3.", asset=host, mitre="T1557",
                    )
        elif packet.protocol == "udp" and dport == 161:
            community = _snmp_community(data)
            if community is not None:
                weak = community in {"public", "private"}
                return Finding(
                    f"insecure:snmp:{server}", "high" if weak else "medium", "insecure_protocol",
                    "SNMP con comunidad por defecto" if weak else "SNMP v1/v2c sin cifrar",
                    f"{packet.source_ip} consulta SNMP v1/v2c en {server}"
                    + (" con la comunidad por defecto: cualquiera puede leer la configuración del equipo." if weak else " (la comunidad viaja en claro)."),
                    "Usa SNMPv3 con autenticación y cifrado, o cambia la comunidad y restringe el acceso por IP.",
                    asset=server, mitre="T1602.001",
                )
        return None


def _snmp_community(data: bytes) -> str | None:
    # SEQUENCE { INTEGER version(0|1), OCTET STRING community, ... }
    try:
        if data[0] != 0x30:
            return None
        offset = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
        if data[offset:offset + 2] != b"\x02\x01" or data[offset + 2] not in (0, 1) or data[offset + 3] != 0x04:
            return None
        length = data[offset + 4]
        return data[offset + 5:offset + 5 + length].decode("ascii", "replace")
    except IndexError:
        return None
