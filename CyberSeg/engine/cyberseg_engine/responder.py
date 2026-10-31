"""Active response (IPS): block attacking addresses in the host firewall.

Blocks live in an nftables set with per-element timeouts, so they expire on
their own even if the engine stops. Repeat offenders get longer blocks. The
engine never blocks protected addresses: this host, its gateway and DNS
servers, trusted administration networks, loopback, multicast or broadcast.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from cyberseg_engine.detections.base import NetworkContext, ip
from cyberseg_engine.models import DetectionAlert, severity_rank

Runner = Callable[[list[str], "str | None"], subprocess.CompletedProcess]

TABLE = "cyberseg"
_SETUP = f"""
add table inet {TABLE}
add set inet {TABLE} blocked4 {{ type ipv4_addr; flags timeout; }}
add set inet {TABLE} blocked6 {{ type ipv6_addr; flags timeout; }}
add chain inet {TABLE} input {{ type filter hook input priority -10; policy accept; }}
add chain inet {TABLE} forward {{ type filter hook forward priority -10; policy accept; }}
add chain inet {TABLE} output {{ type filter hook output priority -10; policy accept; }}
flush chain inet {TABLE} input
flush chain inet {TABLE} forward
flush chain inet {TABLE} output
add rule inet {TABLE} input ip saddr @blocked4 counter drop
add rule inet {TABLE} input ip6 saddr @blocked6 counter drop
add rule inet {TABLE} forward ip saddr @blocked4 counter drop
add rule inet {TABLE} forward ip6 saddr @blocked6 counter drop
add rule inet {TABLE} forward ip daddr @blocked4 counter drop
add rule inet {TABLE} forward ip6 daddr @blocked6 counter drop
add rule inet {TABLE} output ip daddr @blocked4 counter drop
add rule inet {TABLE} output ip6 daddr @blocked6 counter drop
"""


class FirewallError(RuntimeError):
    pass


def _run(arguments: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(arguments, input=stdin, text=True, capture_output=True, check=False, timeout=10)


class NftablesFirewall:
    """Drop traffic from/to blocked IPs for this host and for Docker-published services."""

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _run

    @staticmethod
    def available() -> bool:
        return shutil.which("nft") is not None

    def setup(self) -> None:
        self._nft(["-f", "-"], _SETUP)

    def block(self, address: str, seconds: int) -> None:
        name = self._set(address)
        # Re-adding an existing element keeps its old timeout: refresh it.
        self._runner(["nft", "delete", "element", "inet", TABLE, name, f"{{ {address} }}"], None)
        self._nft(["add", "element", "inet", TABLE, name, f"{{ {address} timeout {seconds}s }}"])

    def unblock(self, address: str) -> None:
        result = self._runner(["nft", "delete", "element", "inet", TABLE, self._set(address), f"{{ {address} }}"], None)
        if result.returncode != 0 and "No such file" not in (result.stderr or ""):
            raise FirewallError((result.stderr or "nft rechazó la orden").strip()[:200])

    def existing(self) -> dict[str, int]:
        """Blocks that survived an engine restart: address -> seconds left."""
        blocks: dict[str, int] = {}
        for name in ("blocked4", "blocked6"):
            result = self._runner(["nft", "-j", "list", "set", "inet", TABLE, name], None)
            if result.returncode != 0:
                continue
            try:
                document = json.loads(result.stdout or "{}")
            except ValueError:
                continue
            for item in document.get("nftables", []):
                for element in item.get("set", {}).get("elem", []):
                    entry = element.get("elem", element) if isinstance(element, dict) else {"val": element}
                    if isinstance(entry.get("val"), str):
                        blocks[entry["val"]] = int(entry.get("expires", entry.get("timeout", 0)) or 0)
        return blocks

    @staticmethod
    def _set(address: str) -> str:
        parsed = ip(address)
        if parsed is None:
            raise FirewallError(f"Dirección inválida: {address!r}")
        return "blocked4" if parsed.version == 4 else "blocked6"

    def _nft(self, arguments: list[str], stdin: str | None = None) -> None:
        result = self._runner(["nft", *arguments], stdin)
        if result.returncode != 0:
            raise FirewallError((result.stderr or result.stdout or "nft rechazó la orden").strip()[:200])


@dataclass(frozen=True, slots=True)
class BlockPolicy:
    mode: str = "block"  # block | dry-run | alert
    min_severity: str = "high"
    base_seconds: int = 3600
    max_seconds: int = 7 * 86400
    block_private: bool = True
    trusted_networks: tuple[str, ...] = ()
    protected_addresses: frozenset[str] = frozenset()


class Responder:
    def __init__(
        self,
        firewall: NftablesFirewall,
        policy: BlockPolicy,
        context: NetworkContext,
        *,
        report_block: Callable[[dict[str, object]], None] = lambda _block: None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._firewall = firewall
        self.policy = policy
        self._context = NetworkContext(context.local_addresses, context.gateway_ip, policy.trusted_networks)
        self._protected = policy.protected_addresses | context.local_addresses | ({context.gateway_ip} - {""})
        self._report = report_block
        self._logger = logger or logging.getLogger("cyberseg.engine.responder")
        self._lock = threading.Lock()
        self._offenses: dict[str, int] = {}
        self._active: dict[str, float] = {}
        self.blocks_applied = 0

    @property
    def active_blocks(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._active = {address: until for address, until in self._active.items() if until > now}
            return len(self._active)

    def handle(self, alert: DetectionAlert) -> DetectionAlert:
        if self.policy.mode == "alert" or severity_rank(alert.risk) < severity_rank(self.policy.min_severity):
            return alert
        if not alert.blockable:
            return self._annotate(alert, "not_blocked", reason="el ataque no se mitiga bloqueando una IP (origen falsificado, capa 2 o revisión manual)")
        target = alert.source_ip
        if self._context.is_local(alert.source_ip) and not self.protection_reason(alert.destination_ip):
            target = alert.destination_ip  # this host reached out to a malicious server
        reason = self.protection_reason(target)
        if reason:
            return self._annotate(alert, "not_blocked", target=target, reason=reason)
        with self._lock:
            remaining = self._active.get(target, 0.0) - time.monotonic()
            if remaining > 0:
                # One attack often fires several signatures at once: the IP is
                # already blocked, so this is not a new offence to escalate.
                return self._annotate(alert, "blocked", target=target, seconds=round(remaining), already_blocked=True)
            offenses = self._offenses.get(target, 0) + 1
            seconds = min(self.policy.max_seconds, self.policy.base_seconds * 4 ** (offenses - 1))
        if self.policy.mode == "dry-run":
            self._logger.warning("[simulación] Se bloquearía %s durante %ss: %s", target, seconds, alert.description)
            return self._annotate(alert, "dry_run", target=target, seconds=seconds)
        try:
            self._firewall.block(target, seconds)
        except (FirewallError, OSError, subprocess.SubprocessError) as error:
            self._logger.error("No se pudo bloquear %s: %s", target, error)
            return self._annotate(alert, "block_failed", target=target, reason=str(error)[:200])
        with self._lock:
            self._offenses[target] = offenses
            if len(self._offenses) > 100_000:
                self._offenses.clear()
            self._active[target] = time.monotonic() + seconds
            self.blocks_applied += 1
        expires = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        self._logger.warning("IP %s bloqueada %s (infracción n.º %s): %s", target, _duration(seconds), offenses, alert.description)
        self._report({
            "ip": target, "reason": alert.description[:300], "severity": alert.risk, "ruleId": alert.rule_id,
            "sensor": alert.sensor, "seconds": seconds, "expiresAt": expires.isoformat(), "offenses": offenses,
        })
        return self._annotate(alert, "blocked", target=target, seconds=seconds, offenses=offenses)

    def restore(self, blocks: dict[str, int]) -> None:
        """Track blocks already in the firewall (they outlive engine restarts)."""
        now = time.monotonic()
        with self._lock:
            for address, seconds_left in blocks.items():
                self._active[address] = now + seconds_left
                self._offenses.setdefault(address, 1)
        if blocks:
            self._logger.info("Se recuperaron %s bloqueos vigentes del firewall.", len(blocks))

    def unblock(self, address: str) -> None:
        self._firewall.unblock(address)
        with self._lock:
            self._active.pop(address, None)
        self._logger.info("IP %s desbloqueada a petición del operador.", address)

    def protection_reason(self, address: str) -> str | None:
        parsed = ip(address)
        if parsed is None:
            return "no es una IP válida"
        if address in self._protected:
            return "es este servidor, su puerta de enlace o un DNS configurado"
        if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified or parsed.is_link_local or parsed.is_reserved:
            return "es una dirección especial no enrutable"
        if address == "255.255.255.255" or address.endswith(".255"):
            return "es una dirección de difusión"
        if self._context.is_trusted(address):
            return "pertenece a CYBERSEG_TRUSTED_NETWORKS"
        if parsed.is_private and not self.policy.block_private:
            return "es una IP privada y CYBERSEG_BLOCK_PRIVATE=false"
        return None

    @staticmethod
    def _annotate(alert: DetectionAlert, action: str, **details: object) -> DetectionAlert:
        return replace(alert, action=action, feature={**alert.feature, "response": {"action": action, **details}})


def _duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        return f"{seconds // 86400} d"
    if seconds % 3600 == 0:
        return f"{seconds // 3600} h"
    return f"{seconds // 60} min"


def read_nameservers(path: str = "/etc/resolv.conf") -> frozenset[str]:
    try:
        with open(path, encoding="utf-8") as handle:
            return frozenset(line.split()[1] for line in handle if line.startswith("nameserver") and len(line.split()) > 1)
    except OSError:
        return frozenset()
