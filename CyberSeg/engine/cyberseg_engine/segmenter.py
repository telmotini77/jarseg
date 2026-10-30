from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cyberseg_engine.models import PacketObservation, TrafficFeature


@dataclass(slots=True)
class TimeWindowSegmenter:
    window_seconds: int = 180
    _window_start: datetime | None = None
    _packets: list[PacketObservation] = field(default_factory=list)

    def add(self, packet: PacketObservation) -> list[TrafficFeature]:
        if self._window_start is None:
            self._window_start = packet.timestamp
        if packet.timestamp - self._window_start < timedelta(seconds=self.window_seconds):
            self._packets.append(packet)
            return []
        completed = self.flush()
        self._window_start = packet.timestamp
        self._packets.append(packet)
        return completed

    def flush(self) -> list[TrafficFeature]:
        if not self._packets or self._window_start is None:
            return []
        window_end = max(packet.timestamp for packet in self._packets)
        groups: dict[tuple[str, str, int], list[PacketObservation]] = defaultdict(list)
        for packet in self._packets:
            groups[(packet.source_ip, packet.destination_ip, packet.destination_port)].append(packet)
        duration = max(1.0, (window_end - self._window_start).total_seconds())
        features = [
            TrafficFeature(
                window_start=self._window_start,
                window_end=window_end,
                source_ip=source,
                destination_ip=destination,
                destination_port=port,
                packets=len(items),
                bytes_total=sum(item.size for item in items),
                packets_per_second=len(items) / duration,
                average_packet_size=sum(item.size for item in items) / len(items),
            )
            for (source, destination, port), items in groups.items()
        ]
        self._packets.clear()
        self._window_start = None
        return features
