from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone


class AutomationScheduler:
    def __init__(self, engine, poll_seconds: float = 20.0, logger: logging.Logger | None = None) -> None:
        self.engine, self.poll_seconds = engine, poll_seconds
        self.logger = logger or logging.getLogger("jarvis.automation.scheduler")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive(): return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="jarvis-automation", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread: self._thread.join(timeout=2)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.engine.run_time(datetime.now(timezone.utc))
            self._stop.wait(self.poll_seconds)
