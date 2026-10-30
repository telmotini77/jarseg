from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone

from app.tasks.manager import ReminderManager
from app.tasks.models import Reminder


class LocalScheduler:
    """Small local scheduler; tests can call run_pending with a deterministic clock."""

    def __init__(
        self,
        reminders: ReminderManager,
        on_reminder: Callable[[Reminder], None],
        poll_seconds: float = 20.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self._reminders = reminders
        self._on_reminder = on_reminder
        self._poll_seconds = poll_seconds
        self._logger = logger or logging.getLogger("jarvis.scheduler")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="jarvis-scheduler", daemon=True)
        self._thread.start()

    def set_reminder_callback(self, callback: Callable[[Reminder], None]) -> None:
        self._on_reminder = callback

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.run_pending(datetime.now(timezone.utc))
            self._stop.wait(self._poll_seconds)

    def run_pending(self, now: datetime) -> list[Reminder]:
        due = self._reminders.due(now)
        for reminder in due:
            self._reminders.mark_triggered(reminder)
            self._logger.info("REMINDER action=trigger trigger=%s", reminder.trigger_at.isoformat())
            self._on_reminder(reminder)
        return due
