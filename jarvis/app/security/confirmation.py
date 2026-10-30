from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.commands.base import Command
from app.commands.classifier import normalize_text


class ConfirmationAnswer(Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PendingConfirmation:
    command: Command
    prompt: str


class ConfirmationManager:
    def __init__(self) -> None:
        self._pending: PendingConfirmation | None = None

    @property
    def pending(self) -> PendingConfirmation | None:
        return self._pending

    def request(self, command: Command, prompt: str) -> None:
        self._pending = PendingConfirmation(command, prompt)

    def resolve(self, text: str) -> ConfirmationAnswer:
        answer = normalize_text(text)
        if answer in {"si", "confirmo", "confirmar", "afirmativo", "dale"}:
            return ConfirmationAnswer.YES
        if answer in {"no", "cancela", "cancelar", "negativo"}:
            return ConfirmationAnswer.NO
        return ConfirmationAnswer.UNKNOWN

    def clear(self) -> None:
        self._pending = None
