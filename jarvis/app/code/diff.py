from __future__ import annotations

import difflib
from pathlib import Path


def unified_diff(path: Path, before: str, after: str, root: Path | None = None, max_lines: int = 240) -> str:
    display = str(path.relative_to(root)) if root and path.is_relative_to(root) else str(path)
    lines = list(difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile=f"a/{display}", tofile=f"b/{display}", lineterm=""))
    if len(lines) > max_lines:
        lines = [*lines[:max_lines], f"... diff truncado ({len(lines) - max_lines} líneas omitidas)"]
    return "\n".join(lines)


def diff_summary(diff: str) -> str:
    added = sum(1 for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in diff.splitlines() if line.startswith("-") and not line.startswith("---"))
    files = sum(1 for line in diff.splitlines() if line.startswith("--- a/"))
    return f"{files} archivos, +{added} líneas, -{removed} líneas"
