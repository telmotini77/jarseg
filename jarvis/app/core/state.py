from __future__ import annotations

from enum import Enum


class AssistantState(str, Enum):
    IDLE = "idle"
    LISTENING = "listening"
    PROCESSING = "processing"
    EXECUTING = "executing"
    SPEAKING = "speaking"
