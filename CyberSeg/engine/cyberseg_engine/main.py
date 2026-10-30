from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cyberseg_engine.detector import AnomalyDetector
from cyberseg_engine.models import PacketObservation
from cyberseg_engine.publisher import AlertPublisher
from cyberseg_engine.segmenter import TimeWindowSegmenter


def _capture_allowed() -> bool:
    return os.getenv("CYBERSEG_CAPTURE_ALLOWED", "false").strip().lower() == "true"


def _sniffer(interface: str, callback):
    from scapy.all import AsyncSniffer, IP, TCP, UDP  # Imported only after explicit operator enablement.

    def observe(packet) -> None:
        if IP not in packet or not (TCP in packet or UDP in packet):
            return
        transport = packet[TCP] if TCP in packet else packet[UDP]
        callback(PacketObservation(
            timestamp=datetime.now(timezone.utc), source_ip=str(packet[IP].src), destination_ip=str(packet[IP].dst),
            source_port=int(transport.sport), destination_port=int(transport.dport),
            protocol="tcp" if TCP in packet else "udp", size=len(packet),
        ))

    return AsyncSniffer(iface=interface, filter="tcp or udp", prn=observe, store=False)


def _capture_requested(api_url: str, token: str) -> bool:
    request = Request(f"{api_url.rstrip('/')}/api/engine/state", headers={"X-CyberSeg-Engine-Token": token})
    try:
        with urlopen(request, timeout=3) as response:
            return bool(__import__("json").loads(response.read().decode("utf-8")).get("captureEnabled"))
    except (HTTPError, URLError, TimeoutError, ValueError):
        return False


def main() -> None:
    if not _capture_allowed():
        print("CyberSeg engine inactivo: CYBERSEG_CAPTURE_ALLOWED=false")
        while True:
            time.sleep(60)
    interface = os.getenv("CYBERSEG_INTERFACE", "").strip()
    if not interface:
        raise RuntimeError("Define CYBERSEG_INTERFACE antes de habilitar captura.")
    segmenter = TimeWindowSegmenter(int(os.getenv("CYBERSEG_WINDOW_SECONDS", "180")))
    detector = AnomalyDetector(float(os.getenv("CYBERSEG_CONTAMINATION", "0.02")))
    api_url, token = os.getenv("CYBERSEG_API_URL", "http://127.0.0.1:8780"), os.environ["CYBERSEG_ENGINE_TOKEN"]
    publisher = AlertPublisher(api_url, token)
    baseline: list = []

    def process(packet: PacketObservation) -> None:
        nonlocal baseline
        for feature in segmenter.add(packet):
            if detector._model is None:
                baseline.append(feature)
                if len(baseline) >= 8:
                    detector.train(baseline)
                continue
            alert = detector.detect(feature)
            if alert is not None:
                publisher.publish(alert)

    while True:
        if not _capture_requested(api_url, token):
            time.sleep(2)
            continue
        sniffer = _sniffer(interface, process)
        sniffer.start()
        print(f"CyberSeg captura local iniciada en {interface}.")
        while _capture_requested(api_url, token):
            time.sleep(2)
        sniffer.stop()
        print("CyberSeg captura detenida por el controlador local.")


if __name__ == "__main__":
    main()
