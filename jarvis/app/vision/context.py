from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class ScreenContext:
    """Ephemeral state for the current desktop; screenshots are never persisted."""

    active_window: str | None
    active_process: str | None
    cursor_position: tuple[int, int]
    screen_width: int
    screen_height: int
    captured_at: datetime
    latest_capture: Any | None = field(default=None, repr=False, compare=False)
