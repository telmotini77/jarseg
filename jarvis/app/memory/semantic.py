from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from app.memory.models import Memory


def _tokens(text: str) -> set[str]:
    return {item for item in re.findall(r"[\wáéíóúñ]{3,}", text.casefold())}


class SemanticMemoryProvider(ABC):
    @abstractmethod
    def add(self, memory: Memory) -> None: ...

    @abstractmethod
    def search(self, query: str, memories: list[Memory], limit: int) -> list[Memory]: ...


class LexicalSemanticMemoryProvider(SemanticMemoryProvider):
    """Local ranking fallback; it can later be replaced by an embedding provider."""

    def add(self, memory: Memory) -> None:
        del memory

    def search(self, query: str, memories: list[Memory], limit: int) -> list[Memory]:
        query_tokens = _tokens(query)
        now = datetime.now(timezone.utc)
        type_aliases = {
            "preference": "preferencia preferencias",
            "fact": "hecho dato datos",
            "project": "proyecto proyectos",
            "task": "tarea tareas",
        }
        ranked: list[tuple[float, Memory]] = []
        for memory in memories:
            memory_tokens = _tokens(
                f"{memory.memory_type} {type_aliases.get(memory.memory_type, '')} {memory.key or ''} {memory.content}"
            )
            overlap = len(query_tokens & memory_tokens) / max(1, len(query_tokens | memory_tokens))
            age_days = max(0.0, (now - memory.updated_at).total_seconds() / 86_400)
            recency = math.exp(-age_days / 180)
            score = overlap * 0.75 + recency * 0.15 + memory.importance * 0.10
            if overlap or query.casefold() in memory.content.casefold():
                ranked.append((score, memory))
        return [memory for _score, memory in sorted(ranked, key=lambda item: item[0], reverse=True)[:limit]]
