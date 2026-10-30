from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WakeWordConfig:
    enabled: bool = True
    wake_word: str = "jarvis"
    provider: str = "transcript"
    command_timeout: int = 8
