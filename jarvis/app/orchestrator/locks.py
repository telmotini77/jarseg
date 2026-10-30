from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager


class ResourceLockManager:
    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def acquire(self, resources: tuple[str, ...]):
        locks = [self._locks.setdefault(resource, asyncio.Lock()) for resource in sorted(set(resources))]
        for lock in locks:
            await lock.acquire()
        try:
            yield
        finally:
            for lock in reversed(locks):
                lock.release()
