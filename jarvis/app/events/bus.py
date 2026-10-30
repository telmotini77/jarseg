from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable

from app.events.models import JarvisEvent


class EventBus:
    """Los eventos son datos observables; nunca constituyen autorización."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._handlers: dict[str, list[Callable[[JarvisEvent], None]]] = defaultdict(list)
        self._all_handlers: list[Callable[[JarvisEvent], None]] = []
        self._logger = logger or logging.getLogger("jarvis.events")

    def subscribe(self, event_type: str, callback: Callable[[JarvisEvent], None]) -> None:
        self._handlers[event_type].append(callback)

    def subscribe_all(self, callback: Callable[[JarvisEvent], None]) -> None:
        self._all_handlers.append(callback)

    def publish(self, event: JarvisEvent) -> None:
        for callback in (*self._all_handlers, *self._handlers[event.event_type]):
            try:
                callback(event)
            except Exception as error:
                self._logger.warning("EVENT handler skipped type=%s reason=%s", event.event_type, type(error).__name__)
