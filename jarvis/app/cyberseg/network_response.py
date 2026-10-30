"""Defensive, local-only firewall response for confirmed CyberSeg alerts."""

from __future__ import annotations

import ipaddress
import logging
import platform
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class FirewallResult:
    source_ip: str
    blocked: bool
    detail: str


class LinuxFirewallBlocker:
    """Add narrowly scoped input-drop rules using an installed Linux firewall.

    The process must already have the firewall administration capability.  This
    class deliberately never invokes sudo or changes firewall defaults.
    """

    def __init__(self, firewall: str = "auto", runner: CommandRunner | None = None) -> None:
        self._firewall = firewall
        self._runner = runner or self._run

    def block(self, source_ip: str) -> FirewallResult:
        if platform.system() != "Linux":
            return FirewallResult(source_ip, False, "Bloqueo automático disponible solo en servidores Linux.")
        firewall = self._resolve_firewall()
        if firewall is None:
            return FirewallResult(source_ip, False, "No se encontró un firewall compatible (ufw, firewalld, nftables o iptables).")
        try:
            if firewall == "iptables":
                return self._block_iptables(source_ip)
            commands = self._commands(firewall, source_ip)
            for command in commands:
                result = self._runner(command)
                if result.returncode != 0:
                    detail = (result.stderr or result.stdout or "el firewall rechazó la regla").strip()
                    return FirewallResult(source_ip, False, f"No se bloqueó {source_ip}: {detail[:180]}")
        except OSError as error:
            return FirewallResult(source_ip, False, f"No se bloqueó {source_ip}: {type(error).__name__}.")
        return FirewallResult(source_ip, True, f"Se bloqueó {source_ip} con {firewall}.")

    def _block_iptables(self, source_ip: str) -> FirewallResult:
        binary = "iptables" if ipaddress.ip_address(source_ip).version == 4 else "ip6tables"
        check = self._runner([binary, "-C", "INPUT", "-s", source_ip, "-j", "DROP"])
        if check.returncode == 0:
            return FirewallResult(source_ip, True, f"{source_ip} ya estaba bloqueada con iptables.")
        result = self._runner([binary, "-I", "INPUT", "1", "-s", source_ip, "-j", "DROP"])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "el firewall rechazó la regla").strip()
            return FirewallResult(source_ip, False, f"No se bloqueó {source_ip}: {detail[:180]}")
        return FirewallResult(source_ip, True, f"Se bloqueó {source_ip} con iptables.")

    def _resolve_firewall(self) -> str | None:
        choices = ("firewalld", "ufw", "nftables", "iptables") if self._firewall == "auto" else (self._firewall,)
        binaries = {"firewalld": "firewall-cmd", "ufw": "ufw", "nftables": "nft", "iptables": "iptables"}
        return next((choice for choice in choices if shutil.which(binaries[choice])), None)

    @staticmethod
    def _commands(firewall: str, source_ip: str) -> list[list[str]]:
        version = ipaddress.ip_address(source_ip).version
        if firewall == "firewalld":
            family = "ipv4" if version == 4 else "ipv6"
            rule = f'rule family="{family}" source address="{source_ip}" drop'
            return [["firewall-cmd", "--quiet", "--add-rich-rule", rule], ["firewall-cmd", "--quiet", "--permanent", "--add-rich-rule", rule]]
        if firewall == "ufw":
            return [["ufw", "--force", "insert", "1", "deny", "from", source_ip]]
        if firewall == "nftables":
            field = "ip" if version == 4 else "ip6"
            return [["nft", "add", "rule", "inet", "filter", "input", field, "saddr", source_ip, "drop"]]
        raise ValueError(f"Firewall no compatible: {firewall}")

    @staticmethod
    def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, text=True, capture_output=True, check=False, timeout=10)


class ServerIntrusionResponder:
    """Only blocks high-confidence source IPs extracted from CyberSeg alerts."""

    _LINE = re.compile(r"\[(?P<risk>[A-Za-z]+)\]\s+(?P<source>[^\s]+)\s+→")
    _RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(
        self,
        blocker: LinuxFirewallBlocker,
        *,
        minimum_risk: str = "high",
        allowlist: tuple[str, ...] = (),
        allow_private_sources: bool = False,
        logger: logging.Logger | None = None,
    ) -> None:
        self._blocker = blocker
        self._minimum_risk = minimum_risk
        self._allow_private_sources = allow_private_sources
        self._logger = logger or logging.getLogger("jarvis.cyberseg.response")
        self._allowlist = self._parse_allowlist(allowlist)
        self._blocked: set[str] = set()

    def handle(self, alerts: str) -> list[str]:
        outcomes: list[str] = []
        for match in self._LINE.finditer(alerts):
            risk = match.group("risk").lower()
            source = match.group("source")
            if self._RISK_ORDER.get(risk, 0) < self._RISK_ORDER[self._minimum_risk]:
                continue
            if source in self._blocked:
                continue
            reason = self._safe_source(source)
            if reason:
                self._logger.info("CyberSeg source skipped: %s", reason)
                outcomes.append(f"No se bloqueó {source}: {reason}")
                continue
            result = self._blocker.block(source)
            if result.blocked:
                self._blocked.add(source)
            outcomes.append(result.detail)
        return outcomes

    def _safe_source(self, source: str) -> str | None:
        try:
            address = ipaddress.ip_address(source)
        except ValueError:
            return "la alerta no contiene una IP de origen válida"
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            return "la dirección es local o no enrutable"
        if address.is_private and not self._allow_private_sources:
            return "es una IP privada; habilita CYBERSEG_SERVER_ALLOW_PRIVATE_SOURCES solo si corresponde"
        if any(address in network for network in self._allowlist):
            return "pertenece a CYBERSEG_SERVER_ALLOWLIST"
        return None

    @staticmethod
    def _parse_allowlist(values: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        networks = []
        for value in values:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as error:
                raise ValueError(f"CYBERSEG_SERVER_ALLOWLIST contiene una red inválida: {value}") from error
        return tuple(networks)
