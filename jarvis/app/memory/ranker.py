"""Ranking explicable de recuerdos: similitud, importancia, confianza y contexto."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone

from app.memory.models import Memory


@dataclass(frozen=True, slots=True)
class RankedMemory:
    memory: Memory
    score: float
    semantic_score: float


class MemoryRanker:
    def rank(
        self,
        candidates: list[tuple[Memory, float]],
        *,
        active_project: str | None = None,
        limit: int = 5,
    ) -> list[RankedMemory]:
        now = datetime.now(timezone.utc)
        result: list[RankedMemory] = []
        for memory, semantic_score in candidates:
            if memory.expires_at and memory.expires_at <= now:
                continue
            age_days = max(0.0, (now - memory.updated_at).total_seconds() / 86_400)
            recency = math.exp(-age_days / 180)
            project = 1.0 if active_project and memory.project_id == active_project else 0.0
            score = semantic_score * 0.45 + memory.importance * 0.2 + memory.confidence * 0.1 + recency * 0.1 + project * 0.15
            result.append(RankedMemory(memory=memory, score=score, semantic_score=semantic_score))
        return sorted(result, key=lambda item: item.score, reverse=True)[:limit]
