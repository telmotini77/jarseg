from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from app.security.permissions import SecurityLevel


class TerminalMode(str, Enum):
    READ_ONLY = "read_only"
    CONFIRM = "confirm"
    EXECUTE = "execute"


class CommandSource(str, Enum):
    USER = "user"
    INTERNAL = "internal"
    WEB_CONTENT = "web_content"
    MODEL = "model"


@dataclass(frozen=True, slots=True)
class TerminalCommand:
    executable: str
    args: tuple[str, ...] = ()
    cwd: Path | None = None
    risk_level: SecurityLevel = SecurityLevel.RESTRICTED
    requires_confirmation: bool = True
    source: CommandSource = CommandSource.USER

    @property
    def argv(self) -> list[str]:
        return [self.executable, *self.args]


@dataclass(frozen=True, slots=True)
class TerminalCommandResult:
    command_id: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool
    success: bool


# Kept as a domain alias for the v0.6 command-result contract.
CommandResult = TerminalCommandResult


@dataclass(frozen=True, slots=True)
class TerminalContext:
    current_directory: Path
    active_project: str | None
    git_repository: bool
    git_branch: str | None
    python_environment: str | None


@dataclass(frozen=True, slots=True)
class TerminalHistoryEntry:
    command_id: str
    executable: str
    args: tuple[str, ...]
    cwd: str | None
    exit_code: int | None
    timestamp: datetime
    risk_level: SecurityLevel
    duration: float


@dataclass(slots=True)
class ManagedProcess:
    id: str
    name: str
    pid: int
    command: TerminalCommand
    started_at: datetime
    status: str = "running"
    output: list[str] = field(default_factory=list, repr=False)


@dataclass(frozen=True, slots=True)
class ToolStatus:
    name: str
    installed: bool
    path: str | None = None
    version: str | None = None
