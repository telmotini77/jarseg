from __future__ import annotations

from pathlib import Path

from app.terminal.models import TerminalContext
from app.terminal.provider import TerminalProvider
from app.terminal.working_directory import WorkingDirectoryManager


class TerminalContextInspector:
    def __init__(self, provider: TerminalProvider, directories: WorkingDirectoryManager) -> None:
        self._provider = provider
        self._directories = directories

    def inspect(self) -> TerminalContext:
        cwd = self._directories.current_directory
        is_git = (cwd / ".git").exists()
        branch: str | None = None
        if is_git:
            result = self._provider.execute(["git", "branch", "--show-current"], cwd, 8.0)
            if result.success:
                branch = result.stdout.strip() or None
        environment = next((str(cwd / name) for name in (".venv", "venv", "env") if (cwd / name).is_dir()), None)
        return TerminalContext(cwd, self._directories.active_project, is_git, branch, environment)
