import json
import os

import pytest

from cyberseg_engine.suricata import EveFollower, SuricataAlertMapper, SuricataSource


def event(signature: str, *, severity: int = 1, category: str = "Attempted Administrator Privilege Gain", sid: int = 2034647, src: str = "203.0.113.7", **extra):
    return {
        "timestamp": "2026-01-01T10:00:00.000000+0000", "event_type": "alert", "src_ip": src, "src_port": 51234,
        "dest_ip": "192.168.1.10", "dest_port": 80, "proto": "TCP", "app_proto": "http",
        "alert": {"signature": signature, "signature_id": sid, "severity": severity, "category": category, **extra},
    }


def test_exploit_signature_maps_to_high_exploitation_with_mitre():
    alert = SuricataAlertMapper().map(event(
        "ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)", metadata={"mitre_technique_id": ["T1190"]},
    ))
    assert (alert.risk, alert.category, alert.mitre, alert.sensor, alert.rule_id) == ("high", "exploitation", "T1190", "suricata", "SID-2034647")
    assert alert.blockable and "CVE-2021-44228" in alert.description


def test_trojan_is_critical_and_reputation_is_high():
    mapper = SuricataAlertMapper()
    trojan = mapper.map(event("ET MALWARE Cobalt Strike Beacon", category="A Network Trojan was detected", sid=1))
    drop = mapper.map(event("ET DROP Spamhaus DROP Listed Traffic Inbound group 1", severity=2, category="Misc Attack", sid=2))
    assert (trojan.risk, trojan.category) == ("critical", "malware")
    assert (drop.risk, drop.category) == ("high", "reputation")


def test_noise_and_low_severity_are_filtered_and_repeats_throttled():
    mapper = SuricataAlertMapper(min_severity="medium")
    assert mapper.map(event("SURICATA STREAM ESTABLISHED packet out of window", severity=3, sid=3)) is None
    assert mapper.map(event("ET INFO Observed DNS Query to .cloud TLD", severity=3, category="Misc activity", sid=4)) is None
    assert mapper.map({"event_type": "flow"}) is None
    first = mapper.map(event("ET SCAN Nmap Scripting Engine User-Agent Detected", severity=2, category="Web Application Attack", sid=5))
    assert first is not None and mapper.map(event("ET SCAN Nmap Scripting Engine User-Agent Detected", severity=2, category="Web Application Attack", sid=5)) is None
    assert mapper.suppressed == 1


def test_attack_response_is_a_compromise_indicator_that_is_not_auto_blocked():
    alert = SuricataAlertMapper().map(event(
        "GPL ATTACK_RESPONSE id check returned root", severity=2, category="Potentially Bad Traffic", sid=2100498, src="192.168.1.10",
    ))
    assert (alert.risk, alert.category, alert.blockable) == ("high", "exploitation", False)


def test_policy_alerts_are_not_blockable():
    alert = SuricataAlertMapper(min_severity="low").map(event("ET POLICY Telnet Session", severity=2, category="Potential Corporate Privacy Violation"))
    assert alert.category == "policy" and not alert.blockable


def write(path, events, mode="a"):
    with open(path, mode, encoding="utf-8", newline="\n") as handle:
        for item in events:
            handle.write(json.dumps(item) + "\n")


def test_follower_skips_history_and_reads_complete_new_lines(tmp_path):
    path = tmp_path / "eve.json"
    write(path, [event("old alert", sid=10)], "w")
    follower = EveFollower(str(path), max_bytes=10**9)
    assert follower.poll() == []  # existing alerts are not replayed

    write(path, [event("new alert", sid=11)])
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write('{"event_type": "alert", "partial')  # line still being written
    assert [item["alert"]["signature_id"] for item in follower.poll()] == [11]

    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write('"}\n')
    follower.poll()
    follower.close()


@pytest.mark.skipif(os.name == "nt", reason="Windows cannot rename a file another handle keeps open; Suricata runs on Linux")
def test_follower_survives_rotation(tmp_path):
    path = tmp_path / "eve.json"
    write(path, [], "w")
    # Rotation: the old file is renamed and Suricata starts a new one.
    follower = EveFollower(str(path), max_bytes=10**9)
    follower.poll()
    os.replace(path, f"{path}.1")
    write(f"{path}.1", [event("tail of old file", sid=12)])
    assert [item["alert"]["signature_id"] for item in follower.poll()] == [12]
    write(path, [event("first in new file", sid=13)], "w")
    follower.poll()  # detects the new file
    assert [item["alert"]["signature_id"] for item in follower.poll()] == [13]
    follower.close()


def test_source_forwards_mapped_alerts(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("", encoding="utf-8")
    emitted: list = []
    source = SuricataSource(EveFollower(str(path)), SuricataAlertMapper(), emitted.append)
    source.poll_once()
    write(path, [event("ET EXPLOIT something", sid=20), {"event_type": "stats"}])
    assert source.poll_once() == 1
    assert source.snapshot()["alertsForwarded"] == 1 and source.snapshot()["connected"] is True
    source.stop()
