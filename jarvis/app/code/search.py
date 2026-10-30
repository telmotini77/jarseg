from __future__ import annotations

import re
from pathlib import Path

from app.code.models import CodeSymbol, ProjectContext, SearchMatch
from app.code.reader import CodeReader
from app.code.symbols import extract_symbols


class CodeSearch:
    def __init__(self, reader: CodeReader | None = None) -> None:
        self.reader = reader or CodeReader()

    def text(self, query: str, context: ProjectContext, limit: int = 30) -> list[SearchMatch]:
        expression = re.compile(re.escape(query), re.IGNORECASE)
        matches: list[SearchMatch] = []
        for item in context.files:
            try:
                content = self.reader.read(item.path, context.root_path)
            except (OSError, ValueError):
                continue
            for number, line in enumerate(content.splitlines(), 1):
                if expression.search(line):
                    matches.append(SearchMatch(item.path, number, line.strip()[:300]))
                    if len(matches) >= limit:
                        return matches
        return matches

    def symbols(self, query: str, context: ProjectContext, limit: int = 30) -> list[SearchMatch]:
        matches: list[SearchMatch] = []
        query_lower = query.casefold()
        for item in context.files:
            try:
                symbols = extract_symbols(item.path, self.reader.read(item.path, context.root_path))
            except (OSError, ValueError):
                continue
            for symbol in symbols:
                if query_lower in symbol.name.casefold():
                    matches.append(SearchMatch(symbol.path, symbol.line, f"{symbol.kind} {symbol.name}", symbol))
                    if len(matches) >= limit:
                        return matches
        return matches

    def references(self, symbol: str, context: ProjectContext, limit: int = 30) -> list[SearchMatch]:
        return self.text(symbol, context, limit)

    def files(self, query: str, context: ProjectContext, limit: int = 30) -> list[Path]:
        needle = query.casefold()
        return [item.path for item in context.files if needle in item.path.name.casefold()][:limit]
