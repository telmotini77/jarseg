"""Detección conservadora de recuerdos repetidos."""

from __future__ import annotations

import re
import unicodedata

from app.memory.models import Memory


def normalized_tokens(text: str) -> set[str]:
    text = unicodedata.normalize("NFKD", text.casefold())
    text = "".join(char for char in text if not unicodedata.combining(char))
    return set(re.findall(r"[a-z0-9_]{3,}", text))


def duplicate_of(content: str, memories: list[Memory], threshold: float = 0.78) -> Memory | None:
    target = normalized_tokens(content)
    for memory in memories:
        current = normalized_tokens(memory.content)
        score = len(target & current) / max(1, len(target | current))
        if score >= threshold:
            return memory
    return None
