from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from app.terminal.models import TerminalCommandResult


class TerminalProvider(ABC):
    """Execution boundary. Implementations receive structured argv only."""

    @abstractmethod
    def execute(
        self,
        command: list[str],
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> TerminalCommandResult: ...
