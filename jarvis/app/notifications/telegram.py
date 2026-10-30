from __future__ import annotations

import hashlib
import http.client
import json
import logging
import threading
import time
from queue import Empty, Full, Queue
from typing import Callable


TelegramSender = Callable[[str, str, float], None]


class TelegramNotifier:
    """Queue Telegram alerts so alert producers never wait for the network.

    A single worker owns a reusable HTTPS connection.  This avoids creating a
    TLS connection for every alert while keeping MQTT callbacks, automations,
    reminder scheduling and the desktop UI responsive.
    """

    _STOP = object()

    def __init__(
        self,
        *,
        token: str,
        chat_id: str,
        enabled: bool = False,
        timeout_seconds: float = 3.0,
        retry_attempts: int = 1,
        queue_size: int = 250,
        deduplication_seconds: float = 3.0,
        logger: logging.Logger | None = None,
        sender: TelegramSender | None = None,
        retry_delay_seconds: float = 0.35,
    ) -> None:
        self._token = token.strip()
        self._chat_id = chat_id.strip()
        self._enabled = enabled and bool(self._token and self._chat_id)
        self._timeout_seconds = max(1.0, timeout_seconds)
        self._retry_attempts = max(0, retry_attempts)
        self._deduplication_seconds = max(0.0, deduplication_seconds)
        self._retry_delay_seconds = max(0.0, retry_delay_seconds)
        self._logger = logger or logging.getLogger("jarvis.telegram")
        self._queue: Queue[str | object] = Queue(maxsize=max(10, queue_size))
        self._recent: dict[str, float] = {}
        self._recent_lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._connection: http.client.HTTPSConnection | None = None
        self._sender = sender or self._send_http

        if enabled and not self._enabled:
            self._logger.warning("Telegram notifications disabled: token or chat ID missing")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def start(self) -> None:
        if not self._enabled or self._worker is not None:
            return
        self._worker = threading.Thread(target=self._run, name="jarvis-telegram", daemon=True)
        self._worker.start()

    def notify(self, message: str) -> bool:
        """Accept an alert immediately; sending happens independently.

        Returns ``False`` if the channel is off, an equal recent alert was
        coalesced, or the bounded queue is full.  No exception from Telegram
        can leak back to an automation or an IoT callback.
        """
        if not self._enabled:
            return False
        normalized = " ".join(message.split())[:4_096]
        if not normalized:
            return False
        fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        now = time.monotonic()
        with self._recent_lock:
            self._discard_expired(now)
            previous = self._recent.get(fingerprint)
            if previous is not None and now - previous < self._deduplication_seconds:
                return False
            self._recent[fingerprint] = now
        try:
            self._queue.put_nowait(normalized)
            return True
        except Full:
            self._logger.warning("Telegram alert dropped: outbound queue is full")
            return False

    def stop(self) -> None:
        self._stop.set()
        if self._worker is not None:
            try:
                self._queue.put_nowait(self._STOP)
            except Full:
                pass
            self._worker.join(timeout=self._timeout_seconds + 1.0)
            self._worker = None
        self._close_connection()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                message = self._queue.get(timeout=0.2)
            except Empty:
                continue
            if message is self._STOP:
                return
            if isinstance(message, str):
                self._send_with_retry(message)

    def _send_with_retry(self, message: str) -> None:
        for attempt in range(self._retry_attempts + 1):
            try:
                self._sender(message, self._chat_id, self._timeout_seconds)
                self._logger.debug("Telegram alert delivered")
                return
            except (OSError, ValueError, http.client.HTTPException) as error:
                self._close_connection()
                if attempt >= self._retry_attempts:
                    self._logger.warning("Telegram alert failed after retries: %s", type(error).__name__)
                    return
                delay = self._retry_delay_seconds * (2 ** attempt)
                if self._stop.wait(delay):
                    return
            except Exception:
                # Third-party sender errors are contained just like HTTP ones.
                self._close_connection()
                self._logger.exception("Telegram alert failed unexpectedly")
                return

    def _send_http(self, message: str, chat_id: str, timeout_seconds: float) -> None:
        if self._connection is None:
            self._connection = http.client.HTTPSConnection("api.telegram.org", timeout=timeout_seconds)
        payload = json.dumps(
            {"chat_id": chat_id, "text": message, "disable_web_page_preview": True},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self._connection.request(
            "POST",
            f"/bot{self._token}/sendMessage",
            body=payload,
            headers={"Content-Type": "application/json", "Connection": "keep-alive"},
        )
        response = self._connection.getresponse()
        response.read()  # Make the HTTP/1.1 connection available to the next alert.
        if not 200 <= response.status < 300:
            raise OSError(f"Telegram HTTP status {response.status}")

    def _discard_expired(self, now: float) -> None:
        if self._deduplication_seconds == 0:
            self._recent.clear()
            return
        cutoff = now - self._deduplication_seconds
        for key, sent_at in tuple(self._recent.items()):
            if sent_at < cutoff:
                self._recent.pop(key, None)

    def _close_connection(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.close()
        except OSError:
            pass
        finally:
            self._connection = None
