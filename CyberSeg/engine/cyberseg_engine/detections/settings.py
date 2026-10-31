from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class DetectionSettings:
    """Thresholds for the behavioural detectors.

    Every field can be overridden from the environment as ``CYBERSEG_<FIELD>``,
    e.g. ``CYBERSEG_SYN_FLOOD_PPS=500``. Defaults suit a single server or a
    small office network; busy networks should raise the flood rates.
    """

    alert_cooldown_seconds: int = 600
    # Layer 2
    arp_reply_flood: int = 30          # ARP replies from one MAC in 10 s
    arp_sweep_hosts: int = 50          # distinct IPs requested by one MAC in 60 s
    mac_flood_macs: int = 1_000        # distinct source MACs in 10 s
    # Layer 3
    ping_sweep_hosts: int = 20         # distinct hosts pinged by one source in 60 s
    icmp_flood_pps: int = 100
    fragment_flood: int = 1_000        # fragments from one source in 10 s
    tiny_fragment_bytes: int = 24
    # Layer 4
    flood_window_seconds: int = 5
    syn_flood_pps: int = 200
    udp_flood_pps: int = 1_000
    reflection_pps: int = 100
    reflection_min_bytes: int = 400
    # Layer 7 and behaviour
    bruteforce_attempts: int = 20
    bruteforce_window_seconds: int = 60
    web_404_responses: int = 40
    dns_unique_subdomains: int = 50
    dns_long_label: int = 50
    dns_nxdomain: int = 30
    beacon_min_connections: int = 8
    beacon_max_jitter: float = 0.15
    lateral_hosts: int = 6
    lateral_window_seconds: int = 300
    exfil_mb: int = 500

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> DetectionSettings:
        values: dict[str, object] = {}
        for item in fields(cls):
            raw = env.get(f"CYBERSEG_{item.name.upper()}", "").strip()
            if not raw:
                continue
            kind = float if isinstance(item.default, float) else int
            try:
                value = kind(raw)
            except ValueError as error:
                raise SystemExit(f"CYBERSEG_{item.name.upper()} debe ser numérico (valor actual: {raw!r}).") from error
            if value <= 0:
                raise SystemExit(f"CYBERSEG_{item.name.upper()} debe ser mayor que cero.")
            values[item.name] = value
        return cls(**values)
