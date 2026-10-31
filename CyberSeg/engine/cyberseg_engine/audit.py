"""Vulnerability and exposure audit of the protected server itself.

Purely local and read-only: listening sockets and network sysctls of the host
network namespace (/proc), the host's sshd configuration (mounted read-only)
and the nftables ruleset. It never probes other machines.
"""

from __future__ import annotations

import glob
import ipaddress
import os
import re
import subprocess
from collections.abc import Callable

from cyberseg_engine.models import Finding

# port -> (service, severity, why it is dangerous when exposed)
RISKY_SERVICES: dict[int, tuple[str, str, str]] = {
    21: ("FTP", "high", "transmite credenciales y archivos sin cifrar"),
    23: ("Telnet", "critical", "transmite credenciales sin cifrar y es objetivo constante de botnets"),
    69: ("TFTP", "high", "no tiene autenticación"),
    111: ("rpcbind", "medium", "revela servicios RPC/NFS y se abusa para amplificación DDoS"),
    135: ("MS-RPC", "high", "permite enumeración y explotación remota de Windows"),
    137: ("NetBIOS", "high", "filtra nombres y recursos de la red"),
    139: ("NetBIOS/SMB", "high", "expone recursos compartidos"),
    161: ("SNMP", "medium", "suele usar comunidades por defecto que filtran la configuración"),
    389: ("LDAP", "medium", "expone el directorio y se abusa para amplificación"),
    445: ("SMB", "high", "es el vector de EternalBlue/WannaCry y de ransomware"),
    512: ("rexec", "critical", "servicio r-* obsoleto sin cifrado"),
    513: ("rlogin", "critical", "servicio r-* obsoleto sin cifrado"),
    514: ("rsh", "critical", "servicio r-* obsoleto sin cifrado"),
    873: ("rsync", "medium", "puede exponer módulos sin autenticación"),
    1433: ("MSSQL", "high", "base de datos expuesta a fuerza bruta y exploits"),
    1521: ("Oracle", "high", "base de datos expuesta a fuerza bruta y exploits"),
    1883: ("MQTT", "medium", "suele funcionar sin TLS ni autenticación"),
    2049: ("NFS", "high", "puede exportar sistemas de archivos a cualquiera"),
    2375: ("API de Docker sin TLS", "critical", "da control total del host (root) a quien se conecte"),
    2379: ("etcd", "high", "guarda secretos del clúster"),
    3306: ("MySQL", "high", "base de datos expuesta a fuerza bruta y exploits"),
    3389: ("RDP", "high", "es el principal vector de entrada de ransomware"),
    5432: ("PostgreSQL", "high", "base de datos expuesta a fuerza bruta y exploits"),
    5900: ("VNC", "high", "suele tener contraseñas débiles y tráfico sin cifrar"),
    5984: ("CouchDB", "high", "ha sufrido RCE sin autenticación"),
    6379: ("Redis", "critical", "por defecto no tiene autenticación y permite ejecutar código"),
    9200: ("Elasticsearch", "high", "suele exponer datos sin autenticación"),
    10250: ("kubelet", "critical", "permite ejecutar comandos en los contenedores"),
    11211: ("memcached", "high", "no tiene autenticación y amplifica DDoS 50.000x"),
    27017: ("MongoDB", "high", "ha filtrado millones de registros por exponerse sin autenticación"),
}

# sysctl -> (expected values, severity, title, recommendation value)
SYSCTL_CHECKS: dict[str, tuple[set[str], str, str, str]] = {
    "net/ipv4/tcp_syncookies": ({"1"}, "high", "SYN cookies desactivadas: el servidor cae ante un SYN flood", "1"),
    "net/ipv4/conf/all/rp_filter": ({"1", "2"}, "medium", "Sin filtrado de ruta inversa: acepta paquetes con IP de origen falsificada", "1"),
    "net/ipv4/conf/all/accept_redirects": ({"0"}, "medium", "Acepta redirecciones ICMP: un atacante puede desviar el tráfico (MITM)", "0"),
    "net/ipv6/conf/all/accept_redirects": ({"0"}, "medium", "Acepta redirecciones ICMPv6: un atacante puede desviar el tráfico (MITM)", "0"),
    "net/ipv4/conf/all/accept_source_route": ({"0"}, "medium", "Acepta paquetes con enrutamiento de origen (source routing)", "0"),
    "net/ipv4/icmp_echo_ignore_broadcasts": ({"1"}, "medium", "Responde a pings de difusión: puede usarse como amplificador Smurf", "1"),
    "net/ipv4/conf/all/log_martians": ({"1"}, "low", "No registra paquetes con direcciones imposibles (martians)", "1"),
}

_SSH_DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes", "permitemptypasswords": "no",
                 "x11forwarding": "no", "maxauthtries": "6"}


def _parse_proc_address(value: str) -> tuple[str, int]:
    address_hex, port_hex = value.split(":")
    raw = bytes.fromhex(address_hex)
    if len(raw) == 4:
        address = str(ipaddress.IPv4Address(raw[::-1]))
    else:
        # /proc stores IPv6 as four 32-bit words in host (little-endian) order.
        address = str(ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))))
    return address, int(port_hex, 16)


def listening_sockets(proc_root: str = "/proc") -> set[tuple[str, str, int]]:
    """(protocol, bind address, port) of every listening TCP / bound UDP socket."""
    sockets: set[tuple[str, str, int]] = set()
    for name, protocol, state in (("tcp", "tcp", "0A"), ("tcp6", "tcp", "0A"), ("udp", "udp", "07"), ("udp6", "udp", "07")):
        try:
            with open(os.path.join(proc_root, "net", name), encoding="ascii") as handle:
                next(handle, None)
                for line in handle:
                    columns = line.split()
                    if len(columns) > 3 and columns[3] == state:
                        address, port = _parse_proc_address(columns[1])
                        sockets.add((protocol, address, port))
        except (OSError, ValueError):
            continue
    return sockets


def _exposed(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    return not parsed.is_loopback


class ServerAuditor:
    def __init__(
        self,
        *,
        proc_root: str = "/proc",
        ssh_dir: str = "/host/etc/ssh",
        host_label: str = "este servidor",
        nft_runner: Callable[[], str | None] | None = None,
    ) -> None:
        self._proc = proc_root
        self._ssh_dir = ssh_dir
        self._host = host_label
        self._nft_runner = nft_runner or _nft_ruleset

    def run(self) -> list[Finding]:
        return [*self.exposed_services(), *self.kernel_hardening(), *self.ssh_configuration(), *self.firewall_policy()]

    def exposed_services(self) -> list[Finding]:
        findings, inventory = [], set()
        for protocol, address, port in sorted(listening_sockets(self._proc)):
            if not _exposed(address):
                continue
            inventory.add(f"{port}/{protocol}")
            risky = RISKY_SERVICES.get(port)
            if risky is None:
                continue
            service, severity, reason = risky
            scope = "todas las interfaces" if address in {"0.0.0.0", "::"} else address
            findings.append(Finding(
                f"audit:port:{protocol}:{port}", severity, "exposed_service", f"{service} expuesto en {port}/{protocol}",
                f"{service} escucha en {scope} de {self._host}: {reason}.",
                f"Si no es imprescindible, desactívalo. Si lo es, publícalo solo en 127.0.0.1 o en la red interna, "
                f"filtra el puerto {port} en el firewall para las IPs autorizadas y exige autenticación fuerte y cifrado.",
                source="audit", asset=f"{self._host}:{port}/{protocol}", mitre="T1190",
            ))
        if inventory:
            ports = ", ".join(sorted(inventory, key=lambda item: (int(item.split("/")[0]), item)))
            findings.append(Finding(
                "audit:ports:inventory", "low", "exposed_service", f"{len(inventory)} puertos abiertos hacia la red",
                f"Servicios accesibles desde fuera de {self._host}: {ports}.",
                "Revisa que cada puerto sea necesario: cada servicio expuesto es superficie de ataque.",
                source="audit", asset=self._host,
            ))
        return findings

    def kernel_hardening(self) -> list[Finding]:
        findings = []
        for key, (expected, severity, title, recommended) in SYSCTL_CHECKS.items():
            try:
                with open(os.path.join(self._proc, "sys", key), encoding="ascii") as handle:
                    value = handle.read().strip()
            except OSError:
                continue
            if value in expected:
                continue
            name = key.replace("/", ".")
            findings.append(Finding(
                f"audit:sysctl:{name}", severity, "hardening", title,
                f"{name} = {value} en {self._host}.",
                f"Ejecuta: echo '{name} = {recommended}' | sudo tee /etc/sysctl.d/90-cyberseg.conf && sudo sysctl --system",
                source="audit", asset=self._host,
            ))
        return findings

    def ssh_configuration(self) -> list[Finding]:
        config = self._read_sshd()
        if config is None:
            return []
        settings = {**_SSH_DEFAULTS, **config}
        findings = []

        def add(key: str, severity: str, title: str, detail: str, recommendation: str) -> None:
            findings.append(Finding(
                f"audit:ssh:{key}", severity, "ssh_config", title, detail, recommendation,
                source="audit", asset=f"{self._host}:ssh", mitre="T1110" if key != "x11forwarding" else "",
            ))

        if settings["permitemptypasswords"] == "yes":
            add("permitemptypasswords", "critical", "SSH acepta contraseñas vacías", "PermitEmptyPasswords yes.",
                "Pon PermitEmptyPasswords no en /etc/ssh/sshd_config y reinicia ssh.")
        if settings["permitrootlogin"] == "yes":
            add("permitrootlogin", "high", "SSH permite entrar como root con contraseña", "PermitRootLogin yes.",
                "Pon PermitRootLogin no (o prohibit-password) y administra con sudo.")
        if settings["passwordauthentication"] == "yes":
            add("passwordauthentication", "medium", "SSH acepta contraseñas (expuesto a fuerza bruta)",
                "PasswordAuthentication yes" + (" (valor por defecto)." if "passwordauthentication" not in config else "."),
                "Usa claves SSH (ssh-copy-id) y después pon PasswordAuthentication no.")
        if settings["x11forwarding"] == "yes":
            add("x11forwarding", "low", "SSH permite reenvío X11", "X11Forwarding yes.", "Pon X11Forwarding no si no lo usas.")
        try:
            if int(settings["maxauthtries"]) > 4:
                add("maxauthtries", "low", "SSH permite muchos intentos por conexión",
                    f"MaxAuthTries {settings['maxauthtries']}.", "Pon MaxAuthTries 3.")
        except ValueError:
            pass
        return findings

    def firewall_policy(self) -> list[Finding]:
        ruleset = self._nft_runner()
        if ruleset is None:
            return []
        if re.search(r"hook input priority [^;]+;\s*policy drop;", ruleset):
            return []
        return [Finding(
            "audit:firewall:input-policy", "medium", "firewall", "Sin firewall de entrada con política por defecto «denegar»",
            f"{self._host} acepta por defecto cualquier conexión entrante a los servicios que escuchan; "
            "CyberSeg solo bloquea las IPs que detecta atacando.",
            "Activa un firewall de mínimo privilegio, p. ej.: sudo ufw default deny incoming && sudo ufw allow OpenSSH && "
            "sudo ufw enable. Recuerda que los puertos publicados por Docker no pasan por ufw: publícalos en 127.0.0.1.",
            source="audit", asset=self._host, mitre="T1190",
        )]

    def _read_sshd(self) -> dict[str, str] | None:
        main = os.path.join(self._ssh_dir, "sshd_config")
        if not os.path.exists(main):
            return None
        values: dict[str, str] = {}

        def parse(path: str) -> None:
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for raw in handle:
                        line = raw.split("#", 1)[0].strip()
                        if not line:
                            continue
                        key, _, value = line.partition(" ")
                        key = key.lower()
                        if key == "match":
                            return  # Match blocks apply conditionally; global options end here
                        if key == "include":
                            for pattern in value.split():
                                pattern = pattern.replace("/etc/ssh", self._ssh_dir) if pattern.startswith("/") else os.path.join(self._ssh_dir, pattern)
                                for included in sorted(glob.glob(pattern)):
                                    parse(included)
                            continue
                        values.setdefault(key, value.strip().lower())  # sshd: the first value wins
            except OSError:
                pass

        parse(main)
        return values


def _nft_ruleset() -> str | None:
    try:
        result = subprocess.run(["nft", "list", "ruleset"], text=True, capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None
