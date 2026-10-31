"""Behavioural detectors grouped by OSI layer.

Each detector exposes ``observe(observation) -> list[DetectionAlert | Finding]``
and ignores observation types it does not handle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyberseg_engine.detections.base import NetworkContext
from cyberseg_engine.detections.layer2 import ArpDetector, MacFloodDetector, RogueServiceDetector
from cyberseg_engine.detections.layer3 import FragmentDetector, IcmpDetector, SpoofingDetector
from cyberseg_engine.detections.layer4 import FloodDetector
from cyberseg_engine.detections.layer7 import (
    BeaconDetector, BruteForceDetector, DnsThreatDetector, InsecureProtocolDetector, LateralMovementDetector,
)
from cyberseg_engine.detections.settings import DetectionSettings

if TYPE_CHECKING:
    from cyberseg_engine.scan_detector import ScanThresholds


def build_detectors(
    settings: DetectionSettings,
    context: NetworkContext,
    *,
    scan: ScanThresholds | None = None,
    scan_allowlist: tuple[str, ...] = (),
    dhcp_servers: tuple[str, ...] = (),
) -> list:
    # Imported here: scan_detector itself builds on detections.base.
    from cyberseg_engine.scan_detector import PortScanDetector

    return [
        ArpDetector(settings, context),
        MacFloodDetector(settings),
        RogueServiceDetector(settings, dhcp_servers),
        IcmpDetector(settings, context),
        SpoofingDetector(settings),
        FragmentDetector(settings),
        PortScanDetector(scan, allowlist=scan_allowlist, local_addresses=context.local_addresses),
        FloodDetector(settings, context),
        BruteForceDetector(settings),
        DnsThreatDetector(settings),
        BeaconDetector(settings),
        LateralMovementDetector(settings, context),
        InsecureProtocolDetector(),
    ]


__all__ = ["DetectionSettings", "NetworkContext", "build_detectors"]
