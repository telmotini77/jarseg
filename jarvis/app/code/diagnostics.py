from __future__ import annotations

import re
from pathlib import Path

from app.code.models import CodeDiagnostic
from app.memory.sensitive_filter import sanitize_for_storage


_PATTERNS = (
    re.compile(r"(?P<path>[^\s:(]+\.(?:ts|tsx|js|jsx|py|cs|java))\((?P<line>\d+),(?P<column>\d+)\):\s*(?:error\s+)?(?P<message>.+)", re.IGNORECASE),
    re.compile(r"File \"(?P<path>[^\"]+)\", line (?P<line>\d+).*(?:\n.+)?", re.IGNORECASE),
    re.compile(r"(?P<path>[^\s:]+\.(?:ts|tsx|js|jsx|py)):(?P<line>\d+):(?P<column>\d+):\s*(?P<message>.+)", re.IGNORECASE),
)


def parse_diagnostics(output: str, root: Path | None = None) -> list[CodeDiagnostic]:
    diagnostics: list[CodeDiagnostic] = []
    safe = sanitize_for_storage(output).content
    for line in safe.splitlines():
        for pattern in _PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            raw_path = match.groupdict().get("path")
            path = (root / raw_path).resolve() if root and raw_path and not Path(raw_path).is_absolute() else Path(raw_path).resolve() if raw_path else None
            diagnostics.append(CodeDiagnostic(
                message=match.groupdict().get("message") or line.strip(), path=path,
                line=int(match.groupdict()["line"]) if match.groupdict().get("line") else None,
                column=int(match.groupdict()["column"]) if match.groupdict().get("column") else None,
            ))
            break
    if not diagnostics and safe.strip():
        diagnostics.append(CodeDiagnostic(safe.splitlines()[-1][:500]))
    return diagnostics
