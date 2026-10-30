from __future__ import annotations

import re
from pathlib import Path

from app.code.models import CodeSymbol


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("class", re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+(\w+)")),
    ("interface", re.compile(r"^\s*(?:export\s+)?interface\s+(\w+)")),
    ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)")),
    ("function", re.compile(r"^\s*def\s+(\w+)")),
    ("method", re.compile(r"^\s*(?:public|private|protected|async|static|readonly|@\w+\([^)]*\)\s*)*(\w+)\s*\([^)]*\)\s*(?::|\{)")),
    ("route", re.compile(r"@(?:Get|Post|Put|Patch|Delete)\s*\((?:['\"]([^'\"]*)['\"])?")),
    ("variable", re.compile(r"^\s*export\s+(?:const|let|var)\s+(\w+)")),
)


def extract_symbols(path: Path, content: str) -> list[CodeSymbol]:
    symbols: list[CodeSymbol] = []
    for number, line in enumerate(content.splitlines(), 1):
        for kind, pattern in _PATTERNS:
            match = pattern.search(line)
            if not match or not match.group(1):
                continue
            symbols.append(CodeSymbol(match.group(1), kind, path, number, exported="export" in line))
            break
    return symbols
