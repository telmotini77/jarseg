import subprocess
from datetime import datetime, timezone

from cyberseg_engine.detections.base import NetworkContext, alert
from cyberseg_engine.responder import TABLE, BlockPolicy, NftablesFirewall, Responder

SERVER, GATEWAY, ADMIN = "192.168.1.10", "192.168.1.1", "192.168.1.50"


class FakeNft:
    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.fail = fail

    def __call__(self, arguments, stdin=None):
        self.calls.append((arguments, stdin))
        failed = self.fail and "add" in arguments
        return subprocess.CompletedProcess(arguments, 1 if failed else 0, "", "Operation not permitted" if failed else "")


def attack(source: str, *, risk: str = "high", blockable: bool = True, destination: str = SERVER):
    return alert(
        datetime(2026, 1, 1, tzinfo=timezone.utc), source, destination, risk=risk, description="Escaneo de puertos",
        category="reconnaissance", rule_id="L4-PORTSCAN", mitre="T1046", layer="L4", blockable=blockable,
    )


def responder(nft: FakeNft, **policy) -> tuple[Responder, list]:
    reported: list = []
    context = NetworkContext(frozenset({SERVER}), GATEWAY)
    defaults = {"trusted_networks": (f"{ADMIN}/32",), "protected_addresses": frozenset({"9.9.9.9"})}
    return Responder(NftablesFirewall(nft), BlockPolicy(**{**defaults, **policy}), context, report_block=reported.append), reported


def test_setup_creates_timed_sets_and_drop_rules():
    nft = FakeNft()
    NftablesFirewall(nft).setup()
    script = nft.calls[0][1]
    assert f"add table inet {TABLE}" in script and "flags timeout" in script
    assert "hook input priority -10" in script and "hook forward" in script and "ip saddr @blocked4 counter drop" in script


def test_high_risk_attacker_is_blocked_with_escalating_duration():
    nft = FakeNft()
    handler, reported = responder(nft)
    first = handler.handle(attack("203.0.113.9"))
    # Several signatures for the same attack while blocked: not a new offence.
    same_attack = handler.handle(attack("203.0.113.9"))
    handler._active["203.0.113.9"] = 0.0  # the first block expired
    repeat = handler.handle(attack("203.0.113.9"))

    assert first.action == "blocked" and first.feature["response"]["seconds"] == 3600
    assert same_attack.feature["response"]["already_blocked"] is True
    assert repeat.feature["response"]["seconds"] == 4 * 3600 and repeat.feature["response"]["offenses"] == 2
    assert ["nft", "add", "element", "inet", TABLE, "blocked4", "{ 203.0.113.9 timeout 3600s }"] in [call[0] for call in nft.calls]
    assert [block["ip"] for block in reported] == ["203.0.113.9", "203.0.113.9"]
    assert handler.active_blocks == 1


def test_ipv6_attacker_goes_to_the_ipv6_set():
    nft = FakeNft()
    handler, _ = responder(nft)
    handler.handle(attack("2001:db8::66"))
    assert any(call[0][5] == "blocked6" for call in nft.calls if call[0][1] == "add")


def test_protected_addresses_are_never_blocked():
    nft = FakeNft()
    handler, reported = responder(nft)
    for source in (SERVER, GATEWAY, ADMIN, "9.9.9.9", "127.0.0.1", "224.0.0.5", "192.168.1.255"):
        result = handler.handle(attack(source, destination=GATEWAY))
        assert result.action == "not_blocked", source
    assert reported == [] and not any(call[0][1] == "add" for call in nft.calls)


def test_private_sources_respect_block_private():
    handler, _ = responder(FakeNft(), block_private=False)
    assert handler.handle(attack("192.168.1.66")).action == "not_blocked"


def test_low_severity_and_unblockable_alerts():
    handler, reported = responder(FakeNft())
    assert handler.handle(attack("203.0.113.9", risk="medium")).action == "alert"
    assert handler.handle(attack("203.0.113.9", blockable=False)).action == "not_blocked"
    assert reported == []


def test_this_server_calling_a_malicious_host_blocks_the_destination():
    handler, reported = responder(FakeNft())
    result = handler.handle(attack(SERVER, risk="critical", destination="93.184.216.34"))
    assert result.feature["response"]["target"] == "93.184.216.34" and reported[0]["ip"] == "93.184.216.34"


def test_dry_run_and_alert_modes_do_not_touch_the_firewall():
    for mode, action in (("dry-run", "dry_run"), ("alert", "alert")):
        nft = FakeNft()
        handler, reported = responder(nft, mode=mode)
        assert handler.handle(attack("203.0.113.9")).action == action
        assert nft.calls == [] and reported == []


def test_blocks_survive_engine_restarts():
    listing = '{"nftables": [{"metainfo": {}}, {"set": {"family": "inet", "name": "blocked4", "elem": [{"elem": {"val": "203.0.113.9", "timeout": 3600, "expires": 1200}}]}}]}'

    def runner(arguments, stdin=None):
        output = listing if arguments[:3] == ["nft", "-j", "list"] and arguments[-1] == "blocked4" else "{}"
        return subprocess.CompletedProcess(arguments, 0, output, "")

    firewall = NftablesFirewall(runner)
    assert firewall.existing() == {"203.0.113.9": 1200}
    handler, reported = responder(FakeNft())
    handler.restore(firewall.existing())
    assert handler.active_blocks == 1
    assert handler.handle(attack("203.0.113.9")).feature["response"]["already_blocked"] is True
    assert reported == []


def test_firewall_failure_is_reported_on_the_alert():
    handler, reported = responder(FakeNft(fail=True))
    result = handler.handle(attack("203.0.113.9"))
    assert result.action == "block_failed" and "Operation not permitted" in result.feature["response"]["reason"]
    assert reported == []
