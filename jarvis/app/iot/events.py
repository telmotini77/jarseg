"""Bus de eventos IoT pequeño y local; los callbacks MQTT no contienen lógica de negocio."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable

from app.iot.models import IoTEvent, IoTEventType


class IoTEventBus:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._listeners: dict[IoTEventType, list[Callable[[IoTEvent], None]]] = defaultdict(list)
        self._logger = logger or logging.getLogger("jarvis.iot.events")

    def subscribe(self, event_type: IoTEventType, callback: Callable[[IoTEvent], None]) -> None:
        self._listeners[event_type].append(callback)

    def publish(self, event: IoTEvent) -> None:
        for callback in tuple(self._listeners[event.event_type]):
            try:
                callback(event)
            except Exception as error:
                self._logger.warning("IOT event callback skipped type=%s reason=%s", event.event_type.value, type(error).__name__)
