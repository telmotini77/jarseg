from datetime import datetime, timedelta, timezone

from cyberseg_engine.detections.base import NetworkContext
from cyberseg_engine.detections.layer2 import ArpDetector, MacFloodDetector, RogueServiceDetector
from cyberseg_engine.detections.layer3 import FragmentDetector, IcmpDetector, SpoofingDetector
from cyberseg_engine.detections.layer4 import FloodDetector
from cyberseg_engine.detections.layer7 import (
    BeaconDetector, BruteForceDetector, DnsThreatDetector, InsecureProtocolDetector, LateralMovementDetector,
)
from cyberseg_engine.detections.settings import DetectionSettings
from cyberseg_engine.models import (
    TCP_ACK, TCP_PSH, TCP_SYN, ArpObservation, DnsObservation, FragmentObservation, IcmpObservation, PacketObservation,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
SERVER, GATEWAY, ATTACKER, PUBLIC = "192.168.1.10", "192.168.1.1", "192.168.1.66", "93.184.216.34"
SETTINGS = DetectionSettings()
CONTEXT = NetworkContext(frozenset({SERVER}), GATEWAY)


def at(seconds: float) -> datetime:
    return NOW + timedelta(seconds=seconds)


def tcp(source, destination, dport, flags=TCP_SYN, *, sport=40000, payload=b"", t=0.0):
    return PacketObservation(at(t), source, destination, sport, dport, "tcp", 60 + len(payload), flags, payload)


def udp(source, destination, dport, *, sport=40000, size=60, payload=b"", t=0.0):
    return PacketObservation(at(t), source, destination, sport, dport, "udp", size, 0, payload)


def run(detector, observations):
    return [result for observation in observations for result in detector.observe(observation)]


# Layer 2 ---------------------------------------------------------------------

def test_gateway_mac_change_is_a_critical_arp_spoof():
    detector = ArpDetector(SETTINGS, CONTEXT)
    alerts = run(detector, [
        ArpObservation(at(0), 2, GATEWAY, "aa:aa:aa:aa:aa:aa", SERVER),
        ArpObservation(at(5), 2, GATEWAY, "bb:bb:bb:bb:bb:bb", SERVER),
    ])
    assert [(a.rule_id, a.risk, a.mitre, a.blockable) for a in alerts] == [("L2-ARP-SPOOF", "critical", "T1557.002", False)]
    assert "puerta de enlace" in alerts[0].description


def test_reassigned_ip_is_not_spoofing_but_gateway_change_always_is():
    detector = ArpDetector(SETTINGS, CONTEXT)
    two_hours = 2 * 3600
    alerts = run(detector, [
        ArpObservation(at(0), 2, "192.168.1.40", "aa:00:00:00:00:01", SERVER),
        ArpObservation(at(two_hours), 2, "192.168.1.40", "aa:00:00:00:00:02", SERVER),  # DHCP reassignment
        ArpObservation(at(0), 2, GATEWAY, "aa:aa:aa:aa:aa:aa", SERVER),
        ArpObservation(at(two_hours), 2, GATEWAY, "bb:bb:bb:bb:bb:bb", SERVER),
    ])
    assert [(a.source_ip, a.risk) for a in alerts] == [(GATEWAY, "critical")]


def test_arp_reply_flood_and_arp_sweep():
    detector = ArpDetector(SETTINGS, CONTEXT)
    replies = run(detector, [ArpObservation(at(i * 0.1), 2, ATTACKER, "cc:cc:cc:cc:cc:cc", f"192.168.1.{i}") for i in range(40)])
    sweep = run(detector, [ArpObservation(at(i * 0.5), 1, "192.168.1.77", "dd:dd:dd:dd:dd:dd", f"192.168.1.{i}") for i in range(2, 80)])
    assert [a.rule_id for a in replies] == ["L2-ARP-POISON"]
    assert [a.rule_id for a in sweep] == ["L2-ARP-SWEEP"]


def test_gateway_arp_requests_are_not_a_sweep():
    detector = ArpDetector(SETTINGS, CONTEXT)
    assert run(detector, [ArpObservation(at(i), 1, GATEWAY, "aa:aa:aa:aa:aa:aa", f"192.168.1.{i}") for i in range(2, 200)]) == []


def test_mac_flood():
    detector = MacFloodDetector(DetectionSettings(mac_flood_macs=500))
    packets = [PacketObservation(at(i / 1000), ATTACKER, SERVER, 1, 2, "tcp", 60, TCP_SYN, b"", f"02:00:00:00:{i // 256:02x}:{i % 256:02x}") for i in range(600)]
    assert [a.rule_id for a in run(detector, packets)] == ["L2-MAC-FLOOD"]


def test_rogue_dhcp_server_after_learning_the_legitimate_one():
    detector = RogueServiceDetector(SETTINGS)
    alerts = run(detector, [udp(GATEWAY, "255.255.255.255", 68, sport=67), udp(ATTACKER, "255.255.255.255", 68, sport=67, t=1)])
    assert [(a.rule_id, a.source_ip, a.risk) for a in alerts] == [("L2-ROGUE-DHCP", ATTACKER, "critical")]


def test_configured_dhcp_server_and_rogue_router_advertisement():
    detector = RogueServiceDetector(SETTINGS, dhcp_servers=("192.168.1.2",))
    assert run(detector, [udp("192.168.1.2", "255.255.255.255", 68, sport=67)]) == []
    ra = [IcmpObservation(at(0), "fe80::1", "ff02::1", 134, 0, 80, 6), IcmpObservation(at(1), "fe80::666", "ff02::1", 134, 0, 80, 6)]
    assert [a.rule_id for a in run(detector, ra)] == ["L2-ROGUE-RA"]


# Layer 3 ---------------------------------------------------------------------

def test_ping_sweep_and_icmp_flood():
    detector = IcmpDetector(SETTINGS, CONTEXT)
    sweep = run(detector, [IcmpObservation(at(i), ATTACKER, f"192.168.1.{i}", 8, 0, 84) for i in range(30, 60)])
    flood = run(detector, [IcmpObservation(at(i / 200), "198.18.0.9", SERVER, 8, 0, 1500) for i in range(600)])
    assert [a.rule_id for a in sweep] == ["L3-PING-SWEEP"]
    assert [a.rule_id for a in flood] == ["L3-ICMP-FLOOD"]


def test_smurf_and_icmp_redirect():
    detector = IcmpDetector(SETTINGS, CONTEXT)
    alerts = run(detector, [IcmpObservation(at(0), "8.8.4.4", "192.168.1.255", 8, 0, 84), IcmpObservation(at(1), ATTACKER, SERVER, 5, 1, 70)])
    assert [a.rule_id for a in alerts] == ["L3-SMURF", "L3-ICMP-REDIRECT"]


def test_land_attack_and_bogon_sources_but_not_dhcp_discover():
    detector = SpoofingDetector(SETTINGS)
    alerts = run(detector, [
        tcp(SERVER, SERVER, 80), tcp("127.0.0.1", SERVER, 22), udp("0.0.0.0", "255.255.255.255", 67, sport=68),
    ])
    assert [a.rule_id for a in alerts] == ["L3-LAND", "L3-BOGON-SOURCE"]


def test_tiny_fragment_and_fragment_flood():
    detector = FragmentDetector(SETTINGS)
    tiny = run(detector, [FragmentObservation(at(0), ATTACKER, SERVER, 0, True, 8, 6)])
    flood = run(detector, [FragmentObservation(at(i / 200), "198.18.0.5", SERVER, 8 * i, True, 1480, 17) for i in range(1, 1100)])
    assert [a.rule_id for a in tiny] == ["L3-TINY-FRAGMENT"]
    assert [a.rule_id for a in flood] == ["L3-FRAGMENT-FLOOD"]


# Layer 4 ---------------------------------------------------------------------

def test_single_source_syn_flood_is_blockable():
    detector = FloodDetector(SETTINGS, CONTEXT)
    alerts = run(detector, [tcp(ATTACKER, SERVER, 80, sport=1000 + i, t=i / 1000) for i in range(1200)])
    assert [(a.rule_id, a.risk, a.blockable, a.source_ip) for a in alerts] == [("L4-SYN-FLOOD", "high", True, ATTACKER)]


def test_distributed_syn_flood_is_critical_and_not_blockable():
    detector = FloodDetector(SETTINGS, CONTEXT)
    alerts = run(detector, [tcp(f"10.{i % 250}.{i // 250}.1", SERVER, 443, t=i / 1000) for i in range(1200)])
    assert [(a.risk, a.blockable) for a in alerts] == [("critical", False)]
    assert "distribuido" in alerts[0].description


def test_udp_flood_and_dns_reflection():
    detector = FloodDetector(SETTINGS, CONTEXT)
    flood = run(detector, [udp(ATTACKER, SERVER, 5060, t=i / 2000) for i in range(5200)])
    reflection = run(detector, [udp(f"8.8.{i % 200}.{i % 50}", SERVER, 40000 + i % 100, sport=53, size=3000, t=i / 1000) for i in range(600)])
    assert [a.rule_id for a in flood] == ["L4-UDP-FLOOD"]
    assert [(a.rule_id, a.risk, a.blockable) for a in reflection] == [("L4-REFLECTION-DDOS", "critical", False)]


def test_normal_web_traffic_is_not_a_flood():
    detector = FloodDetector(SETTINGS, CONTEXT)
    assert run(detector, [tcp(f"203.0.113.{i % 200}", SERVER, 443, t=i / 10) for i in range(2000)]) == []


# Layer 7 ---------------------------------------------------------------------

def test_ssh_brute_force():
    detector = BruteForceDetector(SETTINGS)
    alerts = run(detector, [tcp(ATTACKER, SERVER, 22, sport=50000 + i, t=i * 2) for i in range(25)])
    assert [(a.rule_id, a.mitre, a.category) for a in alerts] == [("L7-BRUTEFORCE-SSH", "T1110", "credential_access")]


def test_web_content_discovery_from_404_responses():
    detector = BruteForceDetector(SETTINGS)
    responses = [tcp(SERVER, ATTACKER, 51000, TCP_ACK | TCP_PSH, sport=80, payload=b"HTTP/1.1 404 Not Found\r\n", t=i) for i in range(45)]
    alerts = run(detector, responses)
    assert [(a.rule_id, a.source_ip) for a in alerts] == [("L7-WEB-DISCOVERY", ATTACKER)]


def test_dns_tunnel_and_dga_nxdomain():
    detector = DnsThreatDetector(SETTINGS)
    tunnel = run(detector, [
        DnsObservation(at(i), SERVER, GATEWAY, f"{'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6'}{i:04x}.exfil.example.com", 16, False, 0, 120)
        for i in range(60)
    ])
    nx = run(detector, [DnsObservation(at(i), GATEWAY, SERVER, f"q{i}xk.biz", 1, True, 3, 90) for i in range(35)])
    assert [(a.rule_id, a.risk) for a in tunnel] == [("L7-DNS-TUNNEL", "high")]
    assert [a.rule_id for a in nx] == ["L7-DNS-NXDOMAIN"]


def test_normal_dns_is_quiet():
    detector = DnsThreatDetector(SETTINGS)
    names = ["www.google.com", "mail.google.com", "api.github.com", "cdn.jsdelivr.net", "ubuntu.com"] * 20
    assert run(detector, [DnsObservation(at(i), SERVER, GATEWAY, name, 1, False, 0, 80) for i, name in enumerate(names)]) == []


def test_regular_beaconing_to_an_external_server():
    detector = BeaconDetector(SETTINGS)
    alerts = run(detector, [tcp(SERVER, PUBLIC, 443, t=i * 60 + (i % 2) * 0.5) for i in range(10)])
    assert [(a.rule_id, a.category, a.blockable) for a in alerts] == [("L7-BEACONING", "command_control", False)]


def test_irregular_browsing_is_not_beaconing():
    detector = BeaconDetector(SETTINGS)
    gaps = [3, 45, 7, 120, 15, 300, 2, 60, 33, 9, 400]
    times = [sum(gaps[:i]) for i in range(len(gaps))]
    assert run(detector, [tcp(SERVER, PUBLIC, 443, t=t) for t in times]) == []


def test_lateral_movement_from_this_server_is_high():
    detector = LateralMovementDetector(SETTINGS, CONTEXT)
    alerts = run(detector, [tcp(SERVER, f"192.168.1.{100 + i}", 445 if i % 2 else 3389, t=i * 10) for i in range(8)])
    assert [(a.rule_id, a.risk) for a in alerts] == [("L7-LATERAL-MOVEMENT", "high")]


def test_insecure_protocols_become_findings_once():
    detector = InsecureProtocolDetector()
    tls10_server_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2D, 0x03, 0x01]) + b"\x00" * 40
    snmp_public = bytes.fromhex("302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")
    findings = run(detector, [
        tcp(ATTACKER, SERVER, 23, TCP_ACK | TCP_PSH, payload=b"login: "),
        tcp(ATTACKER, SERVER, 21, TCP_ACK | TCP_PSH, payload=b"USER admin\r\n"),
        tcp(ATTACKER, SERVER, 21, TCP_ACK | TCP_PSH, payload=b"PASS secret\r\n"),
        tcp(ATTACKER, SERVER, 8080, TCP_ACK | TCP_PSH, payload=b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n"),
        tcp(SERVER, ATTACKER, 51000, TCP_ACK | TCP_PSH, sport=445, payload=b"\x00\x00\x00\x55\xffSMBr" + b"\x00" * 20),
        tcp(SERVER, ATTACKER, 51001, TCP_ACK | TCP_PSH, sport=443, payload=tls10_server_hello),
        udp(ATTACKER, SERVER, 161, payload=snmp_public),
    ])
    assert [f.title for f in findings] == [
        "Telnet en uso", "Credenciales FTP sin cifrar", "Autenticación HTTP Basic sin cifrar", "SMBv1 habilitado",
        "TLS 1.0 negociado", "SNMP con comunidad por defecto",
    ]
    assert all("secret" not in f.detail and "YWRtaW4" not in f.detail for f in findings)
