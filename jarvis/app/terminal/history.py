from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from app.terminal.models import TerminalCommand, TerminalCommandResult, TerminalHistoryEntry
from app.terminal.security import redact_args


class TerminalHistory:
    """Stores metadata only; command output and secret values are never persisted."""

    def __init__(self, path: Path | None = None, limit: int = 100) -> None:
        self.path = path
        self.limit = limit
        self._entries: list[TerminalHistoryEntry] = []

    def add(self, command: TerminalCommand, result: TerminalCommandResult) -> TerminalHistoryEntry:
        entry = TerminalHistoryEntry(
            result.command_id,
            command.executable,
            redact_args(command.args),
            str(command.cwd) if command.cwd else None,
            result.exit_code,
            datetime.now(timezone.utc),
            command.risk_level,
            result.duration,
        )
        self._entries.append(entry)
        del self._entries[:-self.limit]
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = asdict(entry)
            payload["timestamp"] = entry.timestamp.isoformat()
            payload["risk_level"] = entry.risk_level.name
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return entry

    def recent(self, limit: int = 10) -> list[TerminalHistoryEntry]:
        return list(reversed(self._entries[-limit:]))
