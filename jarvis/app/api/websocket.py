from __future__ import annotations

import asyncio
import threading
from collections import deque
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any

from fastapi.encoders import jsonable_encoder
from fastapi import WebSocket

from app.events.models import JarvisEvent


def public_data(value: Any) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return {str(key): public_data(item) for key, item in value.items() if not any(secret in str(key).casefold() for secret in ("password", "token", "secret", "api_key", "authorization"))}
    if isinstance(value, (list, tuple, set)):
        return [public_data(item) for item in value]
    return jsonable_encoder(value)


class WebSocketGateway:
    def __init__(self, history_size: int = 250) -> None:
        self._clients: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = []
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._lock = threading.Lock()

    @property
    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)

    def publish(self, event: JarvisEvent) -> None:
        message = {
            "type": event.event_type.lower().replace("_", "."),
            "source": event.source,
            "data": public_data(event.payload),
            "timestamp": event.timestamp.isoformat(),
            "trace_id": event.trace_id,
        }
        with self._lock:
            self._history.append(message)
            clients = tuple(self._clients)
        for loop, queue in clients:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, message)
            except RuntimeError:
                pass

    async def serve(self, websocket: WebSocket) -> None:
        await websocket.accept()
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        with self._lock:
            self._clients.append((loop, queue))
        try:
            await websocket.send_json({"type": "connected", "data": {"history": self.history[-30:]}})
            while True:
                message = await queue.get()
                await websocket.send_json(message)
        finally:
            with self._lock:
                self._clients = [item for item in self._clients if item[1] is not queue]
