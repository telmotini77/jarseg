from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, ICMPv6ND_RA, IPv6, Raw

from cyberseg_engine.dissect import dissect
from cyberseg_engine.models import (
    TCP_SYN, ArpObservation, DnsObservation, FragmentObservation, IcmpObservation, PacketObservation,
)


def build(packet):
    packet = packet.__class__(bytes(packet))  # behave like a captured frame
    packet.time = 1_767_225_600.0
    return packet


def test_arp_reply():
    [observation] = dissect(build(Ether(src="aa:bb:cc:dd:ee:ff") / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff", pdst="192.168.1.10")))
    assert observation == ArpObservation(observation.timestamp, 2, "192.168.1.1", "aa:bb:cc:dd:ee:ff", "192.168.1.10")


def test_tcp_syn_keeps_flags_payload_and_mac():
    [observation] = dissect(build(Ether(src="02:00:00:00:00:01") / IP(src="203.0.113.5", dst="192.168.1.10") / TCP(sport=4444, dport=22, flags="S") / Raw(b"hi")))
    assert isinstance(observation, PacketObservation)
    assert (observation.destination_port, observation.tcp_flags, observation.payload, observation.source_mac) == (22, TCP_SYN, b"hi", "02:00:00:00:00:01")


def test_dns_query_yields_transport_and_dns_observations():
    observations = dissect(build(Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="abc.example.com", qtype="TXT"))))
    assert [type(item) for item in observations] == [PacketObservation, DnsObservation]
    dns = observations[1]
    assert (dns.query, dns.query_type, dns.is_response) == ("abc.example.com.", 16, False)


def test_icmp_and_icmpv6_router_advertisement():
    [ping] = dissect(build(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / ICMP(type=8)))
    [ra] = dissect(build(Ether() / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_RA()))
    assert (ping.icmp_type, ping.version) == (8, 4)
    assert isinstance(ra, IcmpObservation) and (ra.icmp_type, ra.version) == (134, 6)


def test_ip_fragments():
    first = build(Ether() / IP(src="10.0.0.5", dst="10.0.0.9", flags="MF", frag=0, proto=6) / Raw(b"\x00" * 8))
    later = build(Ether() / IP(src="10.0.0.5", dst="10.0.0.9", frag=3, proto=6) / Raw(b"\x00" * 100))
    first_obs = dissect(first)
    assert isinstance(first_obs[0], FragmentObservation) and first_obs[0].payload_size == 8 and first_obs[0].more_fragments
    [later_obs] = dissect(later)
    assert (later_obs.offset, later_obs.more_fragments) == (24, False)
