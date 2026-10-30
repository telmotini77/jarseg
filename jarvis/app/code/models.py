from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class CodeAgentMode(str, Enum):
    READ_ONLY = "read_only"
    ASSIST = "assist"
    AUTO_FIX = "auto_fix"


class CodeRiskLevel(str, Enum):
    SAFE = "safe"
    CONFIRMATION = "confirmation"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


@dataclass(frozen=True, slots=True)
class ProjectFile:
    path: Path
    language: str | None
    size: int
    modified_at: datetime


@dataclass(frozen=True, slots=True)
class ProjectContext:
    name: str
    root_path: Path
    languages: list[str]
    frameworks: list[str]
    package_managers: list[str]
    git_branch: str | None
    has_tests: bool
    entry_points: list[Path]
    files: list[ProjectFile] = field(default_factory=list, repr=False)


@dataclass(frozen=True, slots=True)
class CodeSymbol:
    name: str
    kind: str
    path: Path
    line: int
    end_line: int | None = None
    exported: bool = False


@dataclass(frozen=True, slots=True)
class SearchMatch:
    path: Path
    line: int
    snippet: str
    symbol: CodeSymbol | None = None


@dataclass(frozen=True, slots=True)
class PatchChange:
    start_line: int
    end_line: int
    replacement: str


@dataclass(frozen=True, slots=True)
class FilePatch:
    path: Path
    original_hash: str | None
    changes: tuple[PatchChange, ...]
    create: bool = False


@dataclass(frozen=True, slots=True)
class CodeChangePlan:
    id: str
    objective: str
    files_to_modify: list[Path]
    files_to_create: list[Path]
    files_to_delete: list[Path]
    validation_steps: list[str]
    risk_level: CodeRiskLevel
    patches: tuple[FilePatch, ...] = ()
    created_at: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True, slots=True)
class PatchApplyResult:
    changed_files: tuple[Path, ...]
    diff: str
    message: str


@dataclass(frozen=True, slots=True)
class CodeDiagnostic:
    message: str
    path: Path | None = None
    line: int | None = None
    column: int | None = None
    severity: str = "error"


@dataclass(frozen=True, slots=True)
class ValidationPlan:
    commands: tuple[tuple[str, ...], ...]
    labels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CodeReviewFinding:
    severity: str
    message: str
    path: Path | None = None
    line: int | None = None
