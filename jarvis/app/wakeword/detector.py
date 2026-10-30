from __future__ import annotations

import logging
from collections.abc import Callable

from app.wakeword.provider import WakeWordProvider


class WakeWordDetector:
    def __init__(self, provider: WakeWordProvider, command_timeout: int, logger: logging.Logger | None = None) -> None:
        self._provider = provider
        self._command_timeout = command_timeout
        self._logger = logger or logging.getLogger("jarvis.wakeword")

    def wait_for_command(self, speaking: Callable[[], bool] | None = None) -> str | None:
        if speaking and speaking():
            return None
        if not self._provider.wait_for_wake_word():
            return None
        self._logger.info("WAKEWORD detected=true")
        return self._provider.capture_command(self._command_timeout)

    def suspend(self) -> None:
        self._provider.suspend()

    def resume(self) -> None:
        self._provider.resume()
