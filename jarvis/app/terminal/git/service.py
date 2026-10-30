from __future__ import annotations

from pathlib import Path

from app.terminal.git.parser import parse_porcelain_status
from app.terminal.git.models import GitStatus
from app.terminal.provider import TerminalProvider


class GitService:
    def __init__(self, provider: TerminalProvider) -> None:
        self._provider = provider

    def status(self, cwd: Path) -> GitStatus | None:
        result = self._provider.execute(["git", "status", "--short", "--branch"], cwd, 15.0)
        return parse_porcelain_status(result.stdout) if result.success else None

    def branch(self, cwd: Path) -> str | None:
        result = self._provider.execute(["git", "branch", "--show-current"], cwd, 10.0)
        return result.stdout.strip() if result.success else None
