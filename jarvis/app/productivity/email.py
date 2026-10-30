from __future__ import annotations

from abc import ABC, abstractmethod

from app.productivity.models import EmailDraft, EmailMessage


class EmailProvider(ABC):
    name: str

    @abstractmethod
    def health(self) -> str: ...

    @abstractmethod
    def search(self, query: str, limit: int = 10) -> list[EmailMessage]: ...

    @abstractmethod
    def create_draft(self, recipient: str, subject: str, body: str, reply_to: str | None = None) -> EmailDraft: ...


def priority(message: EmailMessage, project: str | None = None) -> tuple[str, str]:
    text = f"{message.subject} {message.snippet}".casefold()
    if any(word in text for word in ("urgent", "urgente", "vence", "deadline", "fallo", "failed")): return "critical", "contiene una señal de urgencia"
    if "IMPORTANT" in message.labels or message.unread or (project and project.casefold() in text): return "high", "marcado importante, no leído o relevante para el proyecto"
    return "normal", "sin señales urgentes"


def summarize(messages: list[EmailMessage], project: str | None = None) -> str:
    if not messages: return "No encontré correos que coincidan."
    important = [(message, priority(message, project)) for message in messages]
    notable = [(message, level) for message, level in important if level[0] in {"critical", "high"}]
    lines = [f"Tienes {len(messages)} correos encontrados."]
    if notable: lines.extend(["Prioritarios:", *[f"{index}. {message.sender} — {message.subject}" for index, (message, _) in enumerate(notable[:5], 1)]])
    return "\n".join(lines)
