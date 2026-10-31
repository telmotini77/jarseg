"""Signature detection: ingest Suricata's EVE alerts (Emerging Threats rules).

Suricata inspects application protocols with tens of thousands of community
signatures (exploits, CVEs, malware, C2, reputation lists). CyberSeg tails its
eve.json, normalises each alert to the same severity/category/MITRE model as
the behavioural detectors, throttles repeats and feeds the active response.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from cyberseg_engine.detections.base import Cooldown
from cyberseg_engine.models import DetectionAlert, severity_rank

_SEVERITY = {1: "high", 2: "medium", 3: "low"}
_CRITICAL_CATEGORIES = frozenset({
    "A Network Trojan was detected", "Successful Administrator Privilege Gain", "Successful User Privilege Gain",
    "Executable code was detected", "Malware Command and Control Activity Detected", "Exploit Kit Activity Detected",
})
# Emerging Threats reputation rules: traffic with addresses on public blocklists.
_REPUTATION_PREFIXES = ("ET DROP", "ET CINS", "ET COMPROMISED", "ET 3CORESec", "ET DSHIELD", "ET TOR")
_CATEGORY_RULES = (
    (("Trojan", "Malware", "Command and Control", "Exploit Kit"), "malware"),
    (("Web Application Attack", "Privilege Gain", "Executable code", "Shellcode", "Exploit"), "exploitation"),
    (("Denial of Service",), "denial_of_service"),
    (("Network Scan", "Information Leak", "Scan"), "reconnaissance"),
    (("Credential", "Password"), "credential_access"),
    (("Policy", "Privacy", "Potentially Bad", "Not Suspicious", "Misc activity", "Unknown"), "policy"),
)


def _category(suricata_category: str) -> str:
    for needles, category in _CATEGORY_RULES:
        if any(needle.lower() in suricata_category.lower() for needle in needles):
            return category
    return "exploitation"


class SuricataAlertMapper:
    def __init__(self, *, min_severity: str = "medium", cooldown_seconds: int = 600) -> None:
        self._min_severity = min_severity
        self._cooldown = Cooldown(cooldown_seconds)
        self.suppressed = 0

    def map(self, event: dict) -> DetectionAlert | None:
        if event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
            return None
        details = event["alert"]
        if details.get("action") == "blocked":
            return None
        signature = str(details.get("signature", "Firma de Suricata"))
        sid = int(details.get("signature_id", 0) or 0)
        suricata_category = str(details.get("category", ""))
        severity = int(details.get("severity", 3) or 3)
        risk = _SEVERITY.get(severity, "low")
        category = _category(suricata_category)
        if severity == 1 and suricata_category in _CRITICAL_CATEGORIES:
            risk = "critical"
        blockable = True
        if signature.startswith(_REPUTATION_PREFIXES):
            risk, category = ("high" if severity_rank(risk) < severity_rank("high") else risk), "reputation"
        elif "ATTACK_RESPONSE" in signature:
            # A server answering with exploit output: evidence of compromise.
            # Its source is the victim, so it is escalated, never auto-blocked.
            risk = "high" if severity_rank(risk) < severity_rank("high") else risk
            category, blockable = "exploitation", False
        if signature.startswith("SURICATA ") and severity > 1:
            return None  # protocol decoder/stream anomalies: noise, not attacks
        if severity_rank(risk) < severity_rank(self._min_severity):
            return None
        source, destination = str(event.get("src_ip", "")), str(event.get("dest_ip", ""))
        now = time.monotonic()
        if self._cooldown.active((sid, source, destination), now):
            self.suppressed += 1
            return None
        self._cooldown.trip((sid, source, destination), now)
        metadata = details.get("metadata") if isinstance(details.get("metadata"), dict) else {}
        techniques = metadata.get("mitre_technique_id") or []
        protocol = str(event.get("app_proto") or event.get("proto", "")).lower()
        try:
            timestamp = datetime.fromisoformat(str(event.get("timestamp", "")).replace("+0000", "+00:00"))
        except ValueError:
            timestamp = datetime.now(timezone.utc)
        source_port, destination_port = event.get("src_port"), event.get("dest_port")
        return DetectionAlert(
            timestamp=timestamp, source_ip=source, destination_ip=destination, risk=risk, score=round(1 - (severity - 1) * 0.2, 2),
            description=(
                f"{signature} ({source}{f':{source_port}' if source_port else ''} → "
                f"{destination}{f':{destination_port}' if destination_port else ''}, {protocol or 'ip'}). Suricata SID {sid}."
            ),
            feature={
                "kind": category, "signature": signature, "signature_id": sid, "suricata_category": suricata_category,
                "suricata_severity": severity, "protocol": protocol, "source_port": source_port,
                "destination_port": destination_port, "flow_id": event.get("flow_id"),
            },
            category=category, rule_id=f"SID-{sid}", mitre=str(techniques[0]) if techniques else "",
            layer="L3" if protocol in {"icmp", "ipv6-icmp"} else "L7", sensor="suricata",
            blockable=blockable and category != "policy",
        )


def reopen_log_files(socket_path: str, timeout: float = 5.0) -> bool:
    """Ask Suricata (unix-command socket) to reopen eve.json after a rotation."""
    family = getattr(socket, "AF_UNIX", None)
    if family is None or not os.path.exists(socket_path):
        return False
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(socket_path)
        for message in ({"version": "0.2"}, {"command": "reopen-log-files"}):
            client.sendall(json.dumps(message).encode())
            reply = _receive_json(client)
            if reply.get("return") != "OK":
                return False
    return True


def _receive_json(client: socket.socket) -> dict:
    buffer = b""
    while len(buffer) < 65_536:
        chunk = client.recv(4096)
        if not chunk:
            break
        buffer += chunk
        try:
            return json.loads(buffer.decode("utf-8", "replace"))
        except ValueError:
            continue
    return {}


class EveFollower:
    """Tail eve.json like ``tail -F``, rotating it when it grows too large."""

    def __init__(self, path: str, *, socket_path: str = "", max_bytes: int = 100_000_000, logger: logging.Logger | None = None) -> None:
        self.path = path
        self._socket_path = socket_path
        self._max_bytes = max_bytes
        self._logger = logger or logging.getLogger("cyberseg.engine.suricata")
        self._handle = None
        self._inode: int | None = None
        self._partial = ""
        self._skip_existing = True  # on start-up, do not replay old alerts

    @property
    def connected(self) -> bool:
        return self._handle is not None

    def poll(self) -> list[dict]:
        if self._handle is None and not self._open():
            return []
        events = self._read()
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            return events  # rotated but not reopened yet: keep draining the old file
        if stat.st_ino != self._inode or stat.st_size < self._handle.tell():
            events += self._read()
            self._handle.close()
            self._handle, self._partial = None, ""
        elif stat.st_size > self._max_bytes:
            self._rotate()
        return events

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _open(self) -> bool:
        try:
            self._handle = open(self.path, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return False
        self._inode = os.fstat(self._handle.fileno()).st_ino
        if self._skip_existing:
            self._handle.seek(0, os.SEEK_END)
            self._skip_existing = False
        self._logger.info("Leyendo alertas de Suricata desde %s.", self.path)
        return True

    def _read(self) -> list[dict]:
        data = self._partial + self._handle.read()
        lines = data.split("\n")
        self._partial = lines.pop()
        events = []
        for line in lines:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict):
                events.append(event)
        return events

    def _rotate(self) -> None:
        rotated = f"{self.path}.1"
        try:
            os.replace(self.path, rotated)
            if reopen_log_files(self._socket_path):
                self._logger.info("eve.json rotado a %s.", rotated)
            else:
                self._logger.warning("eve.json rotado, pero Suricata no confirmó reopen-log-files.")
        except OSError as error:
            self._logger.warning("No se pudo rotar eve.json: %s", error)


class SuricataSource:
    """Background thread that forwards Suricata alerts to the engine's queue."""

    def __init__(self, follower: EveFollower, mapper: SuricataAlertMapper, emit: Callable[[DetectionAlert], None], *, logger: logging.Logger | None = None) -> None:
        self._follower = follower
        self._mapper = mapper
        self._emit = emit
        self._logger = logger or logging.getLogger("cyberseg.engine.suricata")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.events_read = 0
        self.alerts_forwarded = 0
        self.last_alert_at: str | None = None

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="cyberseg-suricata", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(5)
        self._follower.close()

    def snapshot(self) -> dict[str, object]:
        return {
            "connected": self._follower.connected, "eventsRead": self.events_read,
            "alertsForwarded": self.alerts_forwarded, "suppressed": self._mapper.suppressed,
            "lastAlertAt": self.last_alert_at,
        }

    def poll_once(self) -> int:
        forwarded = 0
        for event in self._follower.poll():
            self.events_read += 1
            alert = self._mapper.map(event)
            if alert is None:
                continue
            forwarded += 1
            self.alerts_forwarded += 1
            self.last_alert_at = alert.timestamp.isoformat()
            self._logger.warning("[%s] Suricata: %s", alert.risk.upper(), alert.description)
            self._emit(alert)
        return forwarded

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                self._logger.exception("Error leyendo eve.json de Suricata")
            self._stop.wait(1.0)
