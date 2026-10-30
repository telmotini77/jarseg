from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from app.automation.action import Action


@dataclass(slots=True)
class ActionQueue:
    """A small, explicit action sequence; it never accepts free-form LLM plans."""

    _actions: deque[Action] = field(default_factory=deque)
    _cancelled: bool = False

    def enqueue(self, action: Action) -> None:
        if self._cancelled:
            return
        self._actions.append(action)

    def pop_next(self) -> Action | None:
        if self._cancelled or not self._actions:
            return None
        return self._actions.popleft()

    def cancel(self) -> None:
        self._cancelled = True
        self._actions.clear()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def pending_count(self) -> int:
        return len(self._actions)
