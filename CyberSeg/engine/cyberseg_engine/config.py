from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from cyberseg_engine.detections.base import ip
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.models import SEVERITIES
from cyberseg_engine.scan_detector import ScanThresholds


def _flag(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    return env.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(env: Mapping[str, str], name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError as error:
        raise SystemExit(f"{name} debe ser un número entero (valor actual: {raw!r}).") from error
    if value < minimum:
        raise SystemExit(f"{name} debe ser al menos {minimum}.")
    return value


def _float(env: Mapping[str, str], name: str, default: float, minimum: float, maximum: float) -> float:
    raw = env.get(name, "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError as error:
        raise SystemExit(f"{name} debe ser numérico (valor actual: {raw!r}).") from error
    if not minimum <= value <= maximum:
        raise SystemExit(f"{name} debe estar entre {minimum} y {maximum}.")
    return value


def _choice(env: Mapping[str, str], name: str, default: str, choices: tuple[str, ...]) -> str:
    value = env.get(name, default).strip().lower() or default
    if value not in choices:
        raise SystemExit(f"{name} debe ser uno de: {', '.join(choices)} (valor actual: {value!r}).")
    return value


def _networks(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    items = tuple(item.strip() for item in env.get(name, "").split(",") if item.strip())
    for item in items:
        address = item.split("/")[0]
        if ip(address) is None:
            raise SystemExit(f"{name} contiene una IP o red inválida: {item!r}.")
    return items


@dataclass(frozen=True, slots=True)
class EngineConfig:
    api_url: str
    token: str
    capture_allowed: bool
    interface: str
    window_seconds: int
    contamination: float
    baseline_min_samples: int
    baseline_min_windows: int
    alert_cooldown_seconds: int
    heartbeat_seconds: int
    scan: ScanThresholds
    allowlist: tuple[str, ...]
    detection: DetectionSettings
    dhcp_servers: tuple[str, ...]
    prevention_mode: str
    block_min_severity: str
    block_seconds: int
    block_max_seconds: int
    block_private: bool
    trusted_networks: tuple[str, ...]
    suricata_enabled: bool
    suricata_eve: str
    suricata_socket: str
    suricata_min_severity: str
    audit_enabled: bool
    audit_interval_hours: int
    ssh_config_dir: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> EngineConfig:
        token = env.get("CYBERSEG_ENGINE_TOKEN", "").strip()
        if not token:
            raise SystemExit("CYBERSEG_ENGINE_TOKEN no está definido: el motor no puede autenticarse ante la API.")
        cooldown = _int(env, "CYBERSEG_ALERT_COOLDOWN_SECONDS", 600)
        return cls(
            api_url=env.get("CYBERSEG_API_URL", "http://127.0.0.1:8780").strip(),
            token=token,
            capture_allowed=_flag(env, "CYBERSEG_CAPTURE_ALLOWED"),
            interface=env.get("CYBERSEG_INTERFACE", "").strip(),
            window_seconds=_int(env, "CYBERSEG_WINDOW_SECONDS", 180, 10),
            contamination=_float(env, "CYBERSEG_CONTAMINATION", 0.02, 0.001, 0.5),
            baseline_min_samples=_int(env, "CYBERSEG_BASELINE_MIN_SAMPLES", 64, 8),
            baseline_min_windows=_int(env, "CYBERSEG_BASELINE_MIN_WINDOWS", 3),
            alert_cooldown_seconds=cooldown,
            heartbeat_seconds=_int(env, "CYBERSEG_HEARTBEAT_SECONDS", 2),
            scan=ScanThresholds(
                window_seconds=_int(env, "CYBERSEG_SCAN_WINDOW_SECONDS", 60, 5),
                distinct_ports=_int(env, "CYBERSEG_SCAN_PORT_THRESHOLD", 15, 3),
                distinct_hosts=_int(env, "CYBERSEG_SCAN_HOST_THRESHOLD", 20, 3),
                stealth_ports=_int(env, "CYBERSEG_SCAN_STEALTH_THRESHOLD", 3),
                cooldown_seconds=cooldown,
            ),
            allowlist=_networks(env, "CYBERSEG_ALLOWLIST"),
            detection=DetectionSettings.from_env(env),
            dhcp_servers=_networks(env, "CYBERSEG_DHCP_SERVERS"),
            prevention_mode=_choice(env, "CYBERSEG_PREVENTION_MODE", "block", ("block", "dry-run", "alert")),
            block_min_severity=_choice(env, "CYBERSEG_BLOCK_MIN_SEVERITY", "high", SEVERITIES),
            block_seconds=_int(env, "CYBERSEG_BLOCK_SECONDS", 3600, 60),
            block_max_seconds=_int(env, "CYBERSEG_BLOCK_MAX_SECONDS", 7 * 86400, 60),
            block_private=_flag(env, "CYBERSEG_BLOCK_PRIVATE", True),
            trusted_networks=_networks(env, "CYBERSEG_TRUSTED_NETWORKS"),
            suricata_enabled=_flag(env, "CYBERSEG_SURICATA_ENABLED", True),
            suricata_eve=env.get("CYBERSEG_SURICATA_EVE", "/var/log/suricata/eve.json").strip(),
            suricata_socket=env.get("CYBERSEG_SURICATA_SOCKET", "/var/run/suricata/suricata-command.socket").strip(),
            suricata_min_severity=_choice(env, "CYBERSEG_SURICATA_MIN_SEVERITY", "medium", SEVERITIES),
            audit_enabled=_flag(env, "CYBERSEG_AUDIT_ENABLED", True),
            audit_interval_hours=_int(env, "CYBERSEG_AUDIT_INTERVAL_HOURS", 6),
            ssh_config_dir=env.get("CYBERSEG_SSH_CONFIG_DIR", "/host/etc/ssh").strip(),
        )
