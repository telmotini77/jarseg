from __future__ import annotations

import json
import logging
import queue
import threading
from collections.abc import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cyberseg_engine.models import DetectionAlert, Finding


class AlertPublisher:
    def __init__(self, api_url: str, token: str, timeout_seconds: int = 3) -> None:
        self.api_url, self.token, self.timeout_seconds = api_url.rstrip("/"), token, timeout_seconds

    def publish(self, alert: DetectionAlert) -> None:
        self._post("/api/alerts", alert.payload())

    def publish_block(self, block: dict[str, object]) -> None:
        self._post("/api/blocks", block)

    def publish_finding(self, finding: Finding) -> None:
        self._post("/api/findings", finding.payload())

    def sync_findings(self, source: str, findings: list[Finding]) -> None:
        self._post("/api/findings/sync", {"source": source, "findings": [item.payload() for item in findings]})

    def heartbeat(self, status: dict[str, object]) -> dict[str, object]:
        """Report engine health; the reply carries the controller's orders."""
        return self._post("/api/engine/heartbeat", status)

    def _post(self, path: str, body: dict[str, object]) -> dict[str, object]:
        request = Request(
            f"{self.api_url}{path}", data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "X-CyberSeg-Engine-Token": self.token},
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                if not 200 <= response.status < 300:
                    raise ConnectionError(f"CyberSeg API respondió {response.status}.")
                payload = json.loads(response.read().decode("utf-8") or "{}")
        except HTTPError as error:
            hint = " (revisa que CYBERSEG_ENGINE_TOKEN coincida con el backend)" if error.code == 401 else ""
            raise ConnectionError(f"CyberSeg API respondió {error.code} en {path}{hint}.") from error
        except (URLError, TimeoutError, OSError, ValueError) as error:
            raise ConnectionError(f"No se pudo contactar la API local de CyberSeg en {self.api_url}.") from error
        return payload if isinstance(payload, dict) else {}


class AlertQueue:
    """Deliver alerts, blocks and findings from one background thread.

    Capture threads only enqueue, so they never wait on the firewall or the API.
    Each alert first goes through ``respond`` (the active response) so the
    stored alert records whether its source was blocked.
    """

    def __init__(
        self,
        publisher: AlertPublisher,
        *,
        respond: Callable[[DetectionAlert], DetectionAlert] | None = None,
        maxsize: int = 5000,
        attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> None:
        self._publisher = publisher
        self.respond = respond or (lambda alert: alert)
        self._queue: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=maxsize)
        self._attempts = attempts
        self._logger = logger or logging.getLogger("cyberseg.engine.publisher")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.published = self.failed = self.dropped = 0

    def submit(self, alert: DetectionAlert) -> None:
        self._put("alert", alert)

    def submit_block(self, block: dict[str, object]) -> None:
        self._put("block", block)

    def submit_finding(self, finding: Finding) -> None:
        self._put("finding", finding)

    def submit_findings_sync(self, source: str, findings: list[Finding]) -> None:
        self._put("sync", (source, findings))

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="cyberseg-alert-publisher", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _put(self, kind: str, item: object) -> None:
        try:
            self._queue.put_nowait((kind, item))
        except queue.Full:
            self.dropped += 1
            self._logger.warning("Cola de publicación llena: se descartó un evento (%s).", kind)

    def _run(self) -> None:
        while not (self._stop.is_set() and self._queue.empty()):
            try:
                kind, item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if kind == "alert":
                try:
                    item = self.respond(item)
                except Exception:
                    self._logger.exception("La respuesta activa falló; se publica la alerta sin bloqueo.")
                send = lambda alert=item: self._publisher.publish(alert)
            elif kind == "block":
                send = lambda block=item: self._publisher.publish_block(block)
            elif kind == "finding":
                send = lambda finding=item: self._publisher.publish_finding(finding)
            else:
                send = lambda sync=item: self._publisher.sync_findings(*sync)
            self._deliver(kind, send)

    def _deliver(self, kind: str, send: Callable[[], None]) -> None:
        for attempt in range(self._attempts):
            try:
                send()
                if kind == "alert":
                    self.published += 1
                return
            except ConnectionError as error:
                if attempt + 1 == self._attempts:
                    self.failed += 1
                    self._logger.error("No se pudo publicar (%s) tras %s intentos: %s", kind, self._attempts, error)
                else:
                    # Returns at once while shutting down, so the queue still drains.
                    self._stop.wait(0.5 * 2**attempt)
