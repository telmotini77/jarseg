from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from collections.abc import Callable

from app.cyberseg.client import CyberSegClient, CyberSegClientError


class CyberSegMonitor:
    """Poll the local CyberSeg service and notify only on meaningful changes."""

    _RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    _RISK_PATTERN = re.compile(r"\[(low|medium|high|critical)\]|(?:risk|severidad)\s*[:=]\s*(low|medium|high|critical)", re.IGNORECASE)
    _INTERFERENCE_PATTERN = re.compile(r"\b(interferencia|interferencias|jamming|jammer)\b", re.IGNORECASE)

    def __init__(
        self,
        client: CyberSegClient,
        notify: Callable[[str], None],
        *,
        poll_seconds: int = 15,
        max_poll_seconds: int = 120,
        retry_attempts: int = 2,
        failure_threshold: int = 3,
        minimum_risk: str = "high",
        clean_report_seconds: int = 0,
        notify_existing: bool = False,
        notify_service_state: bool = False,
        alert_handler: Callable[[str], list[str]] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._client = client
        self._notify = notify
        self._poll_seconds = max(5, poll_seconds)
        self._max_poll_seconds = max(self._poll_seconds, max_poll_seconds)
        self._retry_attempts = max(0, retry_attempts)
        self._failure_threshold = max(1, failure_threshold)
        self._minimum_risk = minimum_risk.lower()
        if self._minimum_risk not in self._RISK_ORDER:
            raise ValueError("minimum_risk debe ser low, medium, high o critical.")
        self._clean_report_seconds = max(0, clean_report_seconds)
        self._notify_existing = notify_existing
        self._notify_service_state = notify_service_state
        self._alert_handler = alert_handler
        self._logger = logger or logging.getLogger("jarvis.cyberseg.monitor")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_alert_fingerprint: str | None = None
        self._alerts_initialized = False
        self._was_available: bool | None = None
        self._consecutive_failures = 0
        self._last_clean_report_at: float | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="jarvis-cyberseg-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._max_poll_seconds + 1)
            self._thread = None

    def poll_once(self) -> None:
        try:
            status = self._request_with_retry(self._client.status)
        except CyberSegClientError as error:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold and self._notify_service_state and self._was_available is not False:
                self._notify("CyberSeg no está disponible. JARVIS seguirá reintentando en segundo plano.")
            if self._consecutive_failures >= self._failure_threshold:
                self._was_available = False
            self._logger.warning(
                "CyberSeg monitor request failed (%s/%s): %s",
                self._consecutive_failures,
                self._failure_threshold,
                type(error).__name__,
            )
            return

        was_unavailable = self._was_available is False
        if self._notify_service_state and self._was_available is False:
            self._notify(f"CyberSeg volvió a estar disponible. {status}")
        self._was_available = True
        self._consecutive_failures = 0
        try:
            alerts = self._request_with_retry(lambda: self._client.recent_alerts(10))
        except CyberSegClientError as error:
            # A failed alert query is not a service outage: health already
            # succeeded. Keep the prior alert baseline and try next cycle.
            self._logger.warning("CyberSeg alert query deferred: %s", type(error).__name__)
            return
        if was_unavailable:
            self._logger.info("CyberSeg recovered after confirmed consecutive failures")
        if alerts == "CyberSeg no tiene alertas registradas.":
            self._last_alert_fingerprint = None
            self._alerts_initialized = True
            self._notify_clean_review_if_due()
            return
        fingerprint = hashlib.sha256(alerts.encode("utf-8")).hexdigest()
        changed = fingerprint != self._last_alert_fingerprint
        initial = not self._alerts_initialized
        self._last_alert_fingerprint = fingerprint
        self._alerts_initialized = True
        security_alerts = self._security_alerts(alerts)
        if security_alerts is None:
            self._notify_clean_review_if_due()
        if changed and security_alerts is not None and (self._notify_existing or not initial):
            title = (
                "Interferencia detectada por CyberSeg"
                if self._INTERFERENCE_PATTERN.search(security_alerts)
                else "Vulneración detectada por CyberSeg"
            )
            message = f"{title}:\n{security_alerts}"
            if self._alert_handler is not None:
                outcomes = self._alert_handler(security_alerts)
                if outcomes:
                    message += "\n\nRespuesta del servidor:\n" + "\n".join(f"- {outcome}" for outcome in outcomes)
            self._notify(message)

    def _notify_clean_review_if_due(self) -> None:
        if self._clean_report_seconds == 0:
            return
        now = time.monotonic()
        if self._last_clean_report_at is not None and now - self._last_clean_report_at < self._clean_report_seconds:
            return
        self._last_clean_report_at = now
        self._notify(
            "Revisión de radar y sistema completada: no se detectaron interferencias ni vulnerabilidades de riesgo alto o crítico."
        )

    def _security_alerts(self, alerts: str) -> str | None:
        """Return only review rows that meet the configured security risk."""
        qualifying = []
        for line in alerts.splitlines():
            match = self._RISK_PATTERN.search(line)
            if match is None:
                continue
            risk = next(value for value in match.groups() if value is not None).lower()
            if self._RISK_ORDER[risk] >= self._RISK_ORDER[self._minimum_risk]:
                qualifying.append(line)
        if not qualifying:
            self._logger.debug("CyberSeg review has no vulnerability at or above %s", self._minimum_risk)
            return None
        return "\n".join(qualifying)

    def _request_with_retry(self, request: Callable[[], str]) -> str:
        last_error: CyberSegClientError | None = None
        for attempt in range(self._retry_attempts + 1):
            try:
                return request()
            except CyberSegClientError as error:
                last_error = error
                if attempt < self._retry_attempts:
                    time.sleep(0.35 * (attempt + 1))
        assert last_error is not None
        raise last_error

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            # Reduce pressure on a service that is demonstrably unavailable,
            # while automatically returning to the normal cadence on recovery.
            failures_over_threshold = max(0, self._consecutive_failures - self._failure_threshold)
            delay = min(self._max_poll_seconds, self._poll_seconds * (2**failures_over_threshold))
            self._stop.wait(delay)
