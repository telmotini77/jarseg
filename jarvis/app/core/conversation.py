from __future__ import annotations

from dataclasses import dataclass

from app.memory.repository import MemoryRepository
from app.memory.sensitive_filter import sanitize_for_storage
from app.memory.summarizer import summarize_messages


@dataclass(frozen=True, slots=True)
class Message:
    role: str
    content: str


class ConversationManager:
    """In-memory, bounded conversation history."""

    def __init__(self, max_turns: int = 8, repository: MemoryRepository | None = None) -> None:
        if max_turns <= 0:
            raise ValueError("max_turns debe ser mayor que cero.")
        self._max_messages = max_turns * 2
        self._messages: list[Message] = []
        self._repository = repository
        self._conversation_id = repository.create_conversation().id if repository else None

    def add_user_message(self, content: str) -> None:
        self._add("user", content)

    def add_assistant_message(self, content: str) -> None:
        self._add("assistant", content)

    def messages(self) -> list[dict[str, str]]:
        return [{"role": item.role, "content": item.content} for item in self._messages]

    def clear(self) -> None:
        self._messages.clear()

    def close(self) -> None:
        if self._repository is not None and self._conversation_id is not None:
            self._repository.finish_conversation(self._conversation_id, summarize_messages(self.messages()))

    def _add(self, role: str, content: str) -> None:
        sanitized = sanitize_for_storage(content)
        cleaned = sanitized.content
        if not cleaned:
            return
        self._messages.append(Message(role=role, content=cleaned))
        self._messages = self._messages[-self._max_messages :]
        if self._repository is not None and self._conversation_id is not None:
            self._repository.add_message(self._conversation_id, role, cleaned)
