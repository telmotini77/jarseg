from __future__ import annotations

from app.terminal.git.models import GitStatus


def parse_porcelain_status(output: str) -> GitStatus:
    lines = [line for line in output.splitlines() if line.strip()]
    branch = next((line[3:].split("...", 1)[0] for line in lines if line.startswith("##")), None)
    untracked = sum(1 for line in lines if line.startswith("??"))
    modified = sum(1 for line in lines if not line.startswith(("##", "??")))
    return GitStatus(branch, modified, untracked)
