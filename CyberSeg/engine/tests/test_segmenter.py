from datetime import datetime, timedelta, timezone

from cyberseg_engine.models import PacketObservation
from cyberseg_engine.segmenter import TimeWindowSegmenter


def test_segmenter_groups_packets_by_flow() -> None:
    now = datetime.now(timezone.utc)
    segmenter = TimeWindowSegmenter(window_seconds=10)
    segmenter.add(PacketObservation(now, "10.0.0.2", "10.0.0.1", 51000, 443, "tcp", 100))
    segmenter.add(PacketObservation(now + timedelta(seconds=2), "10.0.0.2", "10.0.0.1", 51001, 443, "tcp", 200))
    features = segmenter.flush()
    assert len(features) == 1
    assert features[0].packets == 2
    assert features[0].bytes_total == 300
