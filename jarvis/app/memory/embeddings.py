"""Embeddings locales deterministas y almacén vectorial SQLite.

No descarga modelos ni transmite recuerdos.  El proveedor se puede sustituir por
uno local más avanzado en una versión futura sin cambiar el repositorio.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from abc import ABC, abstractmethod

from app.memory.models import Memory
from app.memory.repository import MemoryRepository


def _normal(text: str) -> list[str]:
    cleaned = unicodedata.normalize("NFKD", text.casefold())
    cleaned = "".join(char for char in cleaned if not unicodedata.combining(char))
    words = re.findall(r"[a-z0-9_]{2,}", cleaned)
    aliases = {
        "seguridad": ("ciberseguridad", "red", "trafico"),
        "ciberseguridad": ("seguridad", "red", "trafico"),
        "trafico": ("red", "seguridad"),
        "redes": ("red",),
        "preferencias": ("preferencia",),
        "proyectos": ("proyecto",),
    }
    expanded: list[str] = []
    for word in words:
        stem = word[:-1] if word.endswith("s") and len(word) > 4 else word
        expanded.extend((word, stem))
        expanded.extend(aliases.get(word, ()))
    return expanded


class EmbeddingProvider(ABC):
    model_name = "unknown"
    version = "1"

    @abstractmethod
    def embed(self, text: str) -> list[float]: ...


class HashEmbeddingProvider(EmbeddingProvider):
    """Representación hashing de 192 dimensiones, privada y sin dependencias."""

    model_name = "local-hash-es-v1"
    dimensions = 192

    def embed(self, text: str) -> list[float]:
        values = [0.0] * self.dimensions
        for token in _normal(text):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
            slot = int.from_bytes(digest[:4], "big") % self.dimensions
            values[slot] += -1.0 if digest[4] & 1 else 1.0
        norm = math.sqrt(sum(value * value for value in values))
        return [value / norm for value in values] if norm else values


def cosine_similarity(first: list[float], second: list[float]) -> float:
    if len(first) != len(second) or not first or not second:
        return 0.0
    return sum(a * b for a, b in zip(first, second))


class VectorStore(ABC):
    @abstractmethod
    def add(self, memory: Memory) -> None: ...

    @abstractmethod
    def search(self, query: str, memories: list[Memory], limit: int) -> list[tuple[Memory, float]]: ...

    @abstractmethod
    def delete(self, memory_id: str) -> None: ...


class SQLiteVectorStore(VectorStore):
    def __init__(self, repository: MemoryRepository, provider: EmbeddingProvider | None = None) -> None:
        self.repository = repository
        self.provider = provider or HashEmbeddingProvider()

    def add(self, memory: Memory) -> None:
        self.repository.set_embedding(
            memory.id,
            self.provider.embed(f"{memory.memory_type} {memory.key or ''} {memory.content}"),
            model=self.provider.model_name,
            version=self.provider.version,
        )

    def search(self, query: str, memories: list[Memory], limit: int) -> list[tuple[Memory, float]]:
        vectors = self.repository.get_embeddings()
        query_vector = self.provider.embed(query)
        ranked = [
            (memory, cosine_similarity(query_vector, vectors[memory.id]))
            for memory in memories
            if memory.id in vectors
        ]
        ranked.sort(key=lambda item: item[1], reverse=True)
        return [item for item in ranked if item[1] > 0.0][:limit]

    def delete(self, memory_id: str) -> None:
        self.repository.delete_embedding(memory_id)
