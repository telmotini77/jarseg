from __future__ import annotations

import shutil
from pathlib import Path

from app.terminal.models import ToolStatus
from app.terminal.provider import TerminalProvider
from app.terminal.registry import COMMAND_REGISTRY, canonical_executable


class EnvironmentInspector:
    def __init__(self, provider: TerminalProvider, timeout: float = 8.0) -> None:
        self._provider = provider
        self._timeout = timeout

    @staticmethod
    def find_executable(name: str) -> str | None:
        return shutil.which(name)

    def is_installed(self, name: str) -> bool:
        canonical = canonical_executable(name)
        tool = COMMAND_REGISTRY.get(canonical)
        return bool(self.find_executable(canonical) or any(self.find_executable(alias) for alias in (tool.aliases if tool else ())))

    def get_version(self, name: str, cwd: Path | None = None) -> str | None:
        canonical = canonical_executable(name)
        if not self.is_installed(canonical):
            return None
        result = self._provider.execute([canonical, "--version"], cwd, self._timeout)
        if not result.success:
            return None
        return next((line.strip() for line in (result.stdout or result.stderr).splitlines() if line.strip()), None)

    def status(self, name: str, cwd: Path | None = None) -> ToolStatus:
        canonical = canonical_executable(name)
        tool = COMMAND_REGISTRY.get(canonical)
        path = self.find_executable(canonical)
        if path is None and tool is not None:
            path = next((self.find_executable(alias) for alias in tool.aliases if self.find_executable(alias)), None)
        return ToolStatus(tool.name if tool else name, bool(path), path, self.get_version(canonical, cwd) if path else None)
