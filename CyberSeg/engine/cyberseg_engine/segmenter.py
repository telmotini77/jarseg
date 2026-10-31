from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cyberseg_engine.models import PacketObservation, TrafficFeature


@dataclass(slots=True)
class TimeWindowSegmenter:
    window_seconds: int = 180
    # Flows are aggregated incrementally (packets, bytes) instead of keeping
    # every packet, and capped so a spoofed-source flood cannot exhaust memory.
    max_flows: int = 100_000
    dropped_packets: int = 0
    _window_start: datetime | None = None
    _window_end: datetime | None = None
    _flows: dict[tuple[str, str, int], list[int]] = field(default_factory=dict)

    def add(self, packet: PacketObservation) -> list[TrafficFeature]:
        completed: list[TrafficFeature] = []
        if self._window_start is not None and packet.timestamp - self._window_start >= timedelta(seconds=self.window_seconds):
            completed = self.flush()
        if self._window_start is None:
            self._window_start = packet.timestamp
        if self._window_end is None or packet.timestamp > self._window_end:
            self._window_end = packet.timestamp
        key = (packet.source_ip, packet.destination_ip, packet.destination_port)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self.max_flows:
                self.dropped_packets += 1
                return completed
            flow = self._flows[key] = [0, 0]
        flow[0] += 1
        flow[1] += packet.size
        return completed

    def flush_expired(self, now: datetime) -> list[TrafficFeature]:
        """Close the current window once its time is up, even without new packets."""
        if self._window_start is not None and now - self._window_start >= timedelta(seconds=self.window_seconds):
            return self.flush()
        return []

    def flush(self) -> list[TrafficFeature]:
        if not self._flows or self._window_start is None:
            self._window_start = self._window_end = None
            return []
        window_start = self._window_start
        window_end = self._window_end or window_start
        duration = max(1.0, (window_end - window_start).total_seconds())
        features = [
            TrafficFeature(
                window_start=window_start,
                window_end=window_end,
                source_ip=source,
                destination_ip=destination,
                destination_port=port,
                packets=packets,
                bytes_total=size,
                packets_per_second=packets / duration,
                average_packet_size=size / packets,
            )
            for (source, destination, port), (packets, size) in self._flows.items()
        ]
        self._flows = {}
        self._window_start = self._window_end = None
        return features
