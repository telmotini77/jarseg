from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GitStatus:
    branch: str | None
    modified: int
    untracked: int
