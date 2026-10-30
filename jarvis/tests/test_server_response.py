from __future__ import annotations

import subprocess

from app.cyberseg.network_response import LinuxFirewallBlocker, ServerIntrusionResponder


class RecordingBlocker:
    def __init__(self) -> None:
        self.sources: list[str] = []

    def block(self, source: str):
        self.sources.append(source)
        from app.cyberseg.network_response import FirewallResult
        return FirewallResult(source, True, f"Se bloqueó {source}.")


def test_server_responder_blocks_only_high_confidence_public_sources() -> None:
    blocker = RecordingBlocker()
    responder = ServerIntrusionResponder(blocker, allowlist=("93.184.216.0/24",))

    outcomes = responder.handle(
        "Alertas recientes de CyberSeg:\n"
        "- [HIGH] 8.8.8.8 → 10.0.0.1: scan\n"
        "- [MEDIUM] 1.1.1.1 → 10.0.0.1: scan\n"
        "- [CRITICAL] 93.184.216.20 → 10.0.0.1: brute force\n"
        "- [HIGH] 192.168.1.50 → 10.0.0.1: scan"
    )

    assert blocker.sources == ["8.8.8.8"]
    assert outcomes[0] == "Se bloqueó 8.8.8.8."
    assert any("ALLOWLIST" in outcome for outcome in outcomes)
    assert any("IP privada" in outcome for outcome in outcomes)


def test_iptables_rule_is_inserted_only_when_it_does_not_exist(monkeypatch) -> None:
    calls: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 1 if "-C" in command else 0, "", "")

    monkeypatch.setattr("app.cyberseg.network_response.platform.system", lambda: "Linux")
    monkeypatch.setattr("app.cyberseg.network_response.shutil.which", lambda binary: "/usr/sbin/iptables" if binary == "iptables" else None)
    result = LinuxFirewallBlocker("iptables", runner=runner).block("8.8.8.8")

    assert result.blocked is True
    assert calls == [
        ["iptables", "-C", "INPUT", "-s", "8.8.8.8", "-j", "DROP"],
        ["iptables", "-I", "INPUT", "1", "-s", "8.8.8.8", "-j", "DROP"],
    ]
