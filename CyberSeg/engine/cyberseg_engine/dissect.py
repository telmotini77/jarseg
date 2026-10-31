"""Translate scapy packets into the engine's observations (one packet may yield several)."""

from __future__ import annotations

from datetime import datetime, timezone

from cyberseg_engine.models import (
    ArpObservation, DnsObservation, FragmentObservation, IcmpObservation, Observation, PacketObservation,
)

CAPTURE_FILTER = "arp or icmp or icmp6 or tcp or udp"
PAYLOAD_BYTES = 2048


def dissect(packet) -> list[Observation]:
    from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6  # Imported only when capture is enabled.

    timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc)
    mac = str(packet[Ether].src) if Ether in packet else ""
    if ARP in packet:
        arp = packet[ARP]
        return [ArpObservation(timestamp, int(arp.op), str(arp.psrc), str(arp.hwsrc), str(arp.pdst))]

    if IP in packet:
        network, version = packet[IP], 4
        fragmented = bool(network.flags.MF) or network.frag > 0
        if fragmented:
            payload_size = max(0, int(network.len) - int(network.ihl) * 4)
            observations: list[Observation] = [FragmentObservation(
                timestamp, str(network.src), str(network.dst), int(network.frag) * 8, bool(network.flags.MF),
                payload_size, int(network.proto),
            )]
            if network.frag > 0:
                return observations  # later fragments carry no transport header
        else:
            observations = []
    elif IPv6 in packet:
        network, version, observations = packet[IPv6], 6, []
    else:
        return []

    source, destination = str(network.src), str(network.dst)
    if version == 4 and ICMP in packet:
        icmp = packet[ICMP]
        observations.append(IcmpObservation(timestamp, source, destination, int(icmp.type), int(icmp.code), len(packet), 4, mac))
        return observations
    if version == 6 and network.nh == 58:
        payload = bytes(network.payload)
        if len(payload) >= 2:
            observations.append(IcmpObservation(timestamp, source, destination, payload[0], payload[1], len(packet), 6, mac))
        return observations

    if TCP in packet:
        transport, protocol, flags = packet[TCP], "tcp", int(packet[TCP].flags)
    elif UDP in packet:
        transport, protocol, flags = packet[UDP], "udp", 0
    else:
        return observations
    observations.append(PacketObservation(
        timestamp, source, destination, int(transport.sport), int(transport.dport), protocol, len(packet), flags,
        bytes(transport.payload)[:PAYLOAD_BYTES], mac,
    ))
    if DNS in packet and 53 in (int(transport.sport), int(transport.dport)):
        dns = packet[DNS]
        questions = dns.qd if isinstance(dns.qd, list) else [dns.qd] if dns.qd is not None else []
        if questions:
            question = questions[0]
            name = question.qname.decode("utf-8", "replace") if isinstance(question.qname, bytes) else str(question.qname)
            observations.append(DnsObservation(
                timestamp, source, destination, name, int(question.qtype), bool(dns.qr), int(dns.rcode), len(packet),
            ))
    return observations
