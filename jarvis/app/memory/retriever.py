"""Recuperación híbrida con degradación segura a búsqueda léxica."""

from __future__ import annotations

import logging

from app.memory.embeddings import VectorStore
from app.memory.models import Memory
from app.memory.ranker import MemoryRanker
from app.memory.repository import MemoryRepository
from app.memory.semantic import SemanticMemoryProvider


class MemoryRetriever:
    def __init__(
        self,
        repository: MemoryRepository,
        vectors: VectorStore,
        lexical: SemanticMemoryProvider,
        ranker: MemoryRanker | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.repository = repository
        self.vectors = vectors
        self.lexical = lexical
        self.ranker = ranker or MemoryRanker()
        self.logger = logger or logging.getLogger("jarvis.memory")

    def search(self, query: str, *, active_project: str | None = None, user_id: str | None = None, limit: int = 5) -> list[Memory]:
        memories = self.repository.list_memories(user_id=user_id)
        try:
            candidates = self.vectors.search(query, memories, max(limit * 3, limit))
        except Exception as error:  # La memoria no debe impedir responder al usuario.
            self.logger.warning("MEMORY vector fallback reason=%s", type(error).__name__)
            candidates = []
        if not candidates:
            lexical = self.lexical.search(query, memories, max(limit * 3, limit))
            candidates = [(memory, 0.35) for memory in lexical]
        ranked = self.ranker.rank(candidates, active_project=active_project, limit=limit)
        for result in ranked:
            self.repository.touch_memory(result.memory.id)
        return [result.memory for result in ranked]
