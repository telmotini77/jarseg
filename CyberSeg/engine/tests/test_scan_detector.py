from datetime import datetime, timedelta, timezone

from cyberseg_engine.models import TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN, TCP_URG, PacketObservation
from cyberseg_engine.scan_detector import PortScanDetector, ScanThresholds, probe_technique

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ATTACKER, SERVER = "203.0.113.50", "198.51.100.10"


def tcp(port: int, flags: int, *, offset: float = 0.0, source: str = ATTACKER, destination: str = SERVER) -> PacketObservation:
    return PacketObservation(NOW + timedelta(seconds=offset), source, destination, 40000, port, "tcp", 60, flags)


def udp(port: int, *, source_port: int = 40000, offset: float = 0.0) -> PacketObservation:
    return PacketObservation(NOW + timedelta(seconds=offset), ATTACKER, SERVER, source_port, port, "udp", 60)


def feed(detector: PortScanDetector, packets) -> list:
    return [alert for packet in packets for alert in detector.observe(packet)]


def test_probe_classification_matches_scan_techniques() -> None:
    assert probe_technique(tcp(22, TCP_SYN)) == "syn"
    assert probe_technique(tcp(22, TCP_SYN | TCP_ACK)) is None
    assert probe_technique(tcp(22, TCP_ACK | TCP_PSH)) is None
    assert probe_technique(tcp(22, 0)) == "null"
    assert probe_technique(tcp(22, TCP_FIN)) == "fin"
    assert probe_technique(tcp(22, TCP_FIN | TCP_PSH | TCP_URG)) == "xmas"
    assert probe_technique(udp(161)) == "udp"
    assert probe_technique(udp(45000, source_port=53)) is None


def test_syn_scan_raises_one_high_alert_per_source() -> None:
    detector = PortScanDetector(ScanThresholds(distinct_ports=15))
    alerts = feed(detector, (tcp(port, TCP_SYN, offset=port * 0.01) for port in range(1, 1001)))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.risk == "high"
    assert alert.source_ip == ATTACKER and alert.destination_ip == SERVER
    assert alert.description.startswith("Escaneo de puertos SYN detectado")
    assert alert.feature["kind"] == "port_scan"
    assert alert.feature["scan_type"] == "vertical"
    assert alert.feature["distinct_ports"] == 15


def test_normal_connections_to_a_few_services_do_not_alert() -> None:
    detector = PortScanDetector()
    packets = [tcp(port, TCP_SYN, offset=index) for index in range(200) for port in (22, 80, 443)]
    packets += [tcp(443, TCP_ACK | TCP_PSH, offset=index) for index in range(500)]

    assert feed(detector, packets) == []


def test_slow_scan_outside_the_window_is_not_counted() -> None:
    detector = PortScanDetector(ScanThresholds(window_seconds=60, distinct_ports=15))
    # One new port every 10 s: never more than 7 distinct ports per minute.
    assert feed(detector, (tcp(port, TCP_SYN, offset=port * 10) for port in range(1, 100))) == []


def test_stealth_xmas_scan_is_detected_quickly() -> None:
    detector = PortScanDetector(ScanThresholds(stealth_ports=3))
    alerts = feed(detector, (tcp(port, TCP_FIN | TCP_PSH | TCP_URG) for port in (21, 22, 23, 25)))

    assert len(alerts) == 1
    assert "sigiloso XMAS" in alerts[0].description
    assert alerts[0].feature["scan_type"] == "stealth"


def test_udp_scan_is_detected() -> None:
    detector = PortScanDetector(ScanThresholds(distinct_ports=15))
    alerts = feed(detector, (udp(port) for port in range(100, 200)))

    assert len(alerts) == 1
    assert "UDP" in alerts[0].description


def test_horizontal_sweep_across_hosts_is_detected() -> None:
    detector = PortScanDetector(ScanThresholds(distinct_hosts=20))
    alerts = feed(detector, (tcp(22, TCP_SYN, destination=f"10.0.0.{host}") for host in range(1, 60)))

    assert len(alerts) == 1
    assert alerts[0].feature["scan_type"] == "horizontal"
    assert "22/TCP" in alerts[0].description


def test_outbound_web_traffic_from_the_server_is_not_a_sweep() -> None:
    detector = PortScanDetector(local_addresses=frozenset({SERVER}))
    packets = [tcp(443, TCP_SYN, source=SERVER, destination=f"192.0.2.{host}") for host in range(1, 200)]
    packets += [tcp(25, TCP_SYN, source=SERVER, destination=f"192.0.2.{host}") for host in range(1, 200)]

    assert feed(detector, packets) == []


def test_allowlisted_scanner_is_ignored() -> None:
    detector = PortScanDetector(allowlist=("203.0.113.0/24",))
    assert feed(detector, (tcp(port, TCP_SYN) for port in range(1, 500))) == []


def test_alert_repeats_after_cooldown() -> None:
    detector = PortScanDetector(ScanThresholds(distinct_ports=15, cooldown_seconds=600))
    first = feed(detector, (tcp(port, TCP_SYN) for port in range(1, 100)))
    during = feed(detector, (tcp(port, TCP_SYN, offset=300) for port in range(100, 200)))
    after = feed(detector, (tcp(port, TCP_SYN, offset=700) for port in range(200, 300)))

    assert (len(first), len(during), len(after)) == (1, 0, 1)


def test_tracking_tables_stay_bounded_under_spoofed_sources() -> None:
    detector = PortScanDetector(ScanThresholds(max_tracked=100))
    feed(detector, (tcp(80 + index % 5, TCP_SYN, source=f"10.{index // 65536}.{index // 256 % 256}.{index % 256}") for index in range(5000)))

    assert len(detector._vertical) <= 100
    assert len(detector._horizontal) <= 100
