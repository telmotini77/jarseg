"""Building blocks shared by the behavioural detectors.

Every structure here is bounded: an attacker who spoofs millions of sources
must not be able to exhaust the engine's memory.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

from cyberseg_engine.models import DetectionAlert, Finding

MAX_TRACKED = 20_000


@dataclass(frozen=True, slots=True)
class NetworkContext:
    """What the engine knows about the host it protects."""

    local_addresses: frozenset[str] = frozenset()
    gateway_ip: str = ""
    trusted_networks: tuple[str, ...] = ()

    def is_local(self, address: str) -> bool:
        return address in self.local_addresses

    def is_trusted(self, address: str) -> bool:
        return _in_networks(address, self.trusted_networks)


@lru_cache(maxsize=65_536)
def ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def is_private(address: str) -> bool:
    parsed = ip(address)
    return parsed is not None and (parsed.is_private or parsed.is_link_local)


def is_public(address: str) -> bool:
    parsed = ip(address)
    return parsed is not None and parsed.is_global


@lru_cache(maxsize=65_536)
def _in_networks(address: str, networks: tuple[str, ...]) -> bool:
    parsed = ip(address)
    if parsed is None or not networks:
        return False
    return any(parsed in ipaddress.ip_network(network, strict=False) for network in networks)


class LruTable(OrderedDict):
    """An OrderedDict that evicts its least recently used keys beyond ``limit``."""

    def __init__(self, factory, limit: int = MAX_TRACKED) -> None:
        super().__init__()
        self._factory = factory
        self._limit = limit

    def touch(self, key):
        value = self.get(key)
        if value is None:
            value = self[key] = self._factory()
            if len(self) > self._limit:
                self.popitem(last=False)
        else:
            self.move_to_end(key)
        return value


class SlidingDistinct:
    """Distinct values seen in the last ``window`` seconds, O(1) per update."""

    __slots__ = ("seen", "labels")

    def __init__(self) -> None:
        self.seen: OrderedDict[object, float] = OrderedDict()
        self.labels: set[str] = set()

    def add(self, now: float, value: object, window: float) -> int:
        self.seen[value] = now
        self.seen.move_to_end(value)
        cutoff = now - window
        while self.seen and next(iter(self.seen.values())) < cutoff:
            self.seen.popitem(last=False)
        return len(self.seen)

    def span(self, now: float) -> int:
        return max(1, round(now - next(iter(self.seen.values())))) if self.seen else 0


class SlidingCount:
    """Events in the last ``window`` seconds, keeping at most ``cap`` timestamps."""

    __slots__ = ("times",)

    def __init__(self, cap: int = 10_000) -> None:
        self.times: deque[float] = deque(maxlen=cap)

    def add(self, now: float, window: float) -> int:
        cutoff = now - window
        while self.times and self.times[0] < cutoff:
            self.times.popleft()
        self.times.append(now)
        return len(self.times)


@dataclass(slots=True)
class TumblingWindow:
    """Fixed windows for rate detections (floods), with per-key counters."""

    start: float = 0.0
    total: int = 0
    by_key: Counter = field(default_factory=Counter)

    def add(self, now: float, window: float, key: object = None, max_keys: int = 5_000) -> bool:
        """Count an event; returns True when a new window started."""
        rolled = now - self.start >= window
        if rolled:
            self.start, self.total = now, 0
            self.by_key.clear()
        self.total += 1
        if key is not None and (key in self.by_key or len(self.by_key) < max_keys):
            self.by_key[key] += 1
        return rolled


class Cooldown:
    """Suppress repeated alerts for the same key for ``seconds``."""

    def __init__(self, seconds: float, limit: int = MAX_TRACKED) -> None:
        self.seconds = seconds
        self._until: OrderedDict[tuple, float] = OrderedDict()
        self._limit = limit

    def active(self, key: tuple, now: float) -> bool:
        until = self._until.get(key)
        if until is None:
            return False
        if until > now:
            return True
        del self._until[key]
        return False

    def trip(self, key: tuple, now: float) -> None:
        self._until[key] = now + self.seconds
        self._until.move_to_end(key)
        if len(self._until) > self._limit:
            self._until.popitem(last=False)


def alert(
    timestamp: datetime,
    source: str,
    destination: str,
    *,
    risk: str,
    description: str,
    category: str,
    rule_id: str,
    mitre: str,
    layer: str,
    score: float = 0.85,
    blockable: bool = True,
    **details: object,
) -> DetectionAlert:
    return DetectionAlert(
        timestamp=timestamp, source_ip=source, destination_ip=destination, risk=risk, description=description,
        score=score, category=category, rule_id=rule_id, mitre=mitre, layer=layer, blockable=blockable,
        feature={"kind": category, "rule": rule_id, "source_ip": source, "destination_ip": destination, **details},
    )


__all__ = [
    "Cooldown", "DetectionAlert", "Finding", "LruTable", "NetworkContext", "SlidingCount", "SlidingDistinct",
    "TumblingWindow", "alert", "ip", "is_private", "is_public",
]
