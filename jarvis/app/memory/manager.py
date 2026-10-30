"""Servicio de Memory Engine 2.0: captura, consulta, control y privacidad."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.memory.context_builder import build_memory_context
from app.memory.deduplicator import duplicate_of
from app.memory.embeddings import EmbeddingProvider, HashEmbeddingProvider, SQLiteVectorStore, VectorStore
from app.memory.models import Memory, MemoryPolicy, MemorySource, MemoryType
from app.memory.project_memory import ProjectMemoryService, slugify
from app.memory.repository import MemoryRepository
from app.memory.retriever import MemoryRetriever
from app.memory.semantic import LexicalSemanticMemoryProvider, SemanticMemoryProvider
from app.memory.sensitive_filter import contains_sensitive_content, sanitize_for_storage
from app.memory.working_memory import WorkingMemoryStore


@dataclass(slots=True)
class ForgetResult:
    deleted: Memory | None = None
    candidates: list[Memory] | None = None


_KIND_ALIASES = {"fact": MemoryType.SEMANTIC, "conversation": MemoryType.EPISODIC, "preference": MemoryType.PREFERENCE, "project": MemoryType.PROJECT, "task": MemoryType.TASK}
_SOURCE_ALIASES = {"user_explicit": MemorySource.USER, "user": MemorySource.USER}


class MemoryManager:
    def __init__(
        self, repository: MemoryRepository, policy: MemoryPolicy = MemoryPolicy.EXPLICIT_ONLY,
        max_results: int = 5, semantic: SemanticMemoryProvider | None = None,
        logger: logging.Logger | None = None, embedding_provider: EmbeddingProvider | None = None,
        vector_store: VectorStore | None = None, context_max_items: int = 10, context_max_tokens: int = 600,
    ) -> None:
        self.repository = repository
        self.policy = policy
        self.max_results = max_results
        self.semantic = semantic or LexicalSemanticMemoryProvider()
        self._logger = logger or logging.getLogger("jarvis.memory")
        self.vectors = vector_store or SQLiteVectorStore(repository, embedding_provider or HashEmbeddingProvider())
        self.retriever = MemoryRetriever(repository, self.vectors, self.semantic, logger=self._logger)
        self.working = WorkingMemoryStore()
        self.projects = ProjectMemoryService(repository)
        self.context_max_items = context_max_items
        self.context_max_tokens = context_max_tokens
        self.last_rejection: str | None = None
        self.active_user_id: str | None = None

    def set_active_user(self, user_id: str | None) -> None:
        self.active_user_id = user_id

    def clear_working(self) -> None:
        self.working = WorkingMemoryStore()

    @staticmethod
    def _memory_type(value: MemoryType | str | None, content: str) -> MemoryType:
        if isinstance(value, MemoryType):
            return value
        if value:
            lowered = value.casefold()
            return _KIND_ALIASES.get(lowered, MemoryType(lowered))
        lowered = content.casefold()
        return MemoryType.PREFERENCE if any(word in lowered for word in ("prefiero", "preferencia", "me gusta")) else MemoryType.SEMANTIC

    @staticmethod
    def _source(value: MemorySource | str) -> MemorySource:
        if isinstance(value, MemorySource):
            return value
        return _SOURCE_ALIASES.get(value.casefold(), MemorySource(value.casefold()))

    @staticmethod
    def _infer_project(content: str) -> str | None:
        match = re.search(r"\b(?:proyecto|project)\s+([\w.-]+)", content, flags=re.IGNORECASE)
        if match:
            return slugify(match.group(1))
        match = re.search(r"^([A-Za-z][\w.-]+)\s+(?:usa|está|esta|tiene|se encuentra)", content)
        return slugify(match.group(1)) if match else None

    @staticmethod
    def _infer_key(content: str, memory_type: MemoryType, project_id: str | None) -> str | None:
        lowered = content.casefold()
        prefix = f"{project_id}:" if project_id else ""
        if memory_type is MemoryType.PREFERENCE and any(word in lowered for word in ("respuesta", "responde", "voz", "corto", "detallado")):
            return "response_style"
        if project_id:
            if any(word in lowered for word in ("ruta", "ubicación", "ubicacion", "carpeta", "path")):
                return prefix + "location"
            if any(word in lowered for word in ("base de datos", "postgres", "mysql", "sqlite", "mongodb")):
                return prefix + "database"
            if any(word in lowered for word in ("tecnología", "tecnologia", "stack", "usa react", "usa python")):
                return prefix + "technologies"
        return None

    def remember(
        self, content: str, memory_type: MemoryType | str | None = None, key: str | None = None, *,
        source: MemorySource | str = MemorySource.USER, project_id: str | None = None,
        importance: float | None = None, confidence: float = 0.9, expires_at: datetime | None = None,
    ) -> Memory | None:
        self.last_rejection = None
        if self.policy is MemoryPolicy.DISABLED:
            self.last_rejection = "La memoria persistente está desactivada."
            return None
        if contains_sensitive_content(content):
            self.last_rejection = "No guardaré credenciales, tokens ni otros secretos."
            self._logger.warning("MEMORY action=reject_sensitive")
            return None
        sanitized = sanitize_for_storage(content)
        if not sanitized.content:
            self.last_rejection = "No hay información útil para guardar."
            return None
        try:
            kind = self._memory_type(memory_type, sanitized.content)
            origin = self._source(source)
        except ValueError:
            self.last_rejection = "El tipo u origen de memoria no es válido."
            return None
        if origin in {MemorySource.MODEL, MemorySource.BROWSER} and kind in {MemoryType.SEMANTIC, MemoryType.PREFERENCE}:
            self.last_rejection = "Solo guardaré hechos o preferencias si los confirmas explícitamente."
            return None
        project_id = project_id or self._infer_project(sanitized.content)
        key = key or self._infer_key(sanitized.content, kind, project_id)
        existing = self.repository.find_by_key(key, project_id=project_id, user_id=self.active_user_id) if key else None
        duplicate = existing or duplicate_of(sanitized.content, self.repository.list_memories(user_id=self.active_user_id))
        default_importance = 0.8 if kind in {MemoryType.PREFERENCE, MemoryType.PROJECT} else 0.65
        if duplicate:
            updated = self.repository.update_memory(
                duplicate.id, content=sanitized.content, memory_type=kind, key=key or duplicate.key,
                source=origin, project_id=project_id or duplicate.project_id,
                importance=importance if importance is not None else max(duplicate.importance, default_importance),
                confidence=confidence, expires_at=expires_at,
            )
            if updated:
                self.vectors.add(updated)
                self.repository.log_audit("update", memory_id=updated.id, details={"deduplicated": True})
                return updated
        memory = self.repository.create_memory(
            sanitized.content, kind, key=key, importance=importance if importance is not None else default_importance,
            source=origin, confidence=confidence, project_id=project_id, expires_at=expires_at,
            user_id=self.active_user_id,
        )
        try:
            self.vectors.add(memory)
        except Exception as error:
            self._logger.warning("MEMORY vector write skipped reason=%s", type(error).__name__)
        self.semantic.add(memory)
        self.repository.log_audit("create", memory_id=memory.id, details={"type": str(kind), "redacted": sanitized.redacted})
        if project_id:
            self.working.update(active_project=project_id)
        self._logger.info("MEMORY action=create type=%s redacted=%s", kind, sanitized.redacted)
        return memory

    def recall(self, query: str, *, active_project: str | None = None, limit: int | None = None) -> list[Memory]:
        if self.policy is MemoryPolicy.DISABLED:
            return []
        self.repository.purge_expired()
        project = active_project or self.working.get().active_project
        results = self.retriever.search(query, active_project=project, user_id=self.active_user_id, limit=limit or self.max_results)
        self.repository.log_audit("recall", details={"query_length": len(query), "results": len(results)})
        return results

    def build_context(self, query: str) -> str:
        return build_memory_context(
            self.recall(query, limit=self.context_max_items), max_items=self.context_max_items, max_tokens=self.context_max_tokens,
        )

    def forget(self, query: str) -> ForgetResult:
        candidates = self.recall(query)
        if len(candidates) != 1:
            return ForgetResult(candidates=candidates)
        deleted = candidates[0]
        if self.repository.delete_memory(deleted.id):
            try:
                self.vectors.delete(deleted.id)
            except Exception:
                pass
            self.repository.log_audit("delete", memory_id=deleted.id)
            return ForgetResult(deleted=deleted)
        return ForgetResult(candidates=[])

    def update(self, query: str, content: str) -> Memory | None:
        candidates = self.recall(query)
        if len(candidates) != 1 or contains_sensitive_content(content):
            return None
        sanitized = sanitize_for_storage(content)
        if not sanitized.content:
            return None
        updated = self.repository.update_memory(candidates[0].id, content=sanitized.content, confidence=1.0)
        if updated:
            self.vectors.add(updated)
            self.repository.log_audit("update", memory_id=updated.id, details={"via": "user_command"})
        return updated

    def why(self, query: str) -> str:
        candidates = self.recall(query, limit=1)
        if not candidates:
            return "No encuentro un recuerdo relacionado."
        memory = candidates[0]
        source = memory.source.value if isinstance(memory.source, MemorySource) else memory.source
        return f"Lo recuerdo porque fue guardado desde {source}, con confianza {memory.confidence:.0%} e importancia {memory.importance:.0%}."

    def when(self, query: str) -> str:
        candidates = self.recall(query, limit=1)
        if not candidates:
            return "No encuentro un recuerdo relacionado."
        return "Se guardó el " + candidates[0].created_at.astimezone().strftime("%d/%m/%Y a las %H:%M") + "."

    def stats(self) -> dict[str, Any]:
        result = self.repository.stats()
        result["working_memory"] = self.working.snapshot()
        return result

    def backup(self, destination: str) -> str:
        path = self.repository.backup_to(destination)
        self.repository.log_audit("backup", details={"destination": str(path)})
        return str(path)

    def export(self, destination: str, query: str | None = None) -> str:
        records = self.recall(query, limit=100) if query else self.repository.list_memories()
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        data = [{"id": item.id, "type": str(item.memory_type), "content": sanitize_for_storage(item.content).content,
                 "project_id": item.project_id, "importance": item.importance, "confidence": item.confidence,
                 "created_at": item.created_at.isoformat()} for item in records]
        target.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        self.repository.log_audit("export", details={"count": len(data)})
        return str(target)

    def clear_all(self) -> int:
        count = self.repository.delete_all_memories()
        self.repository.log_audit("clear_all", details={"count": count})
        return count

    def reindex(self) -> int:
        indexed = 0
        for memory in self.repository.list_memories():
            self.vectors.add(memory)
            indexed += 1
        self.repository.log_audit("reindex", details={"count": indexed})
        return indexed

    def update_working(self, **changes: Any) -> None:
        self.working.update(**changes)

    def remember_terminal_result(self, command: str, success: bool, output: str = "") -> Memory | None:
        self.working.update(last_command=command, last_error=None if success else output[:300])
        if self.policy is not MemoryPolicy.SMART or (success and not output):
            return None
        status = "correctamente" if success else "con error"
        return self.remember(
            f"Comando terminal ejecutado {status}: {command}. Resultado: {output[:700]}", MemoryType.EPISODIC,
            source=MemorySource.TERMINAL, importance=0.45 if success else 0.7,
            expires_at=datetime.now(timezone.utc) + timedelta(days=14),
        )

    def remember_browser_reference(self, url: str, title: str | None = None) -> Memory | None:
        self.working.update(last_url=url)
        if self.policy is not MemoryPolicy.SMART:
            return None
        return self.remember(
            f"Página visitada: {title or url} ({url})", MemoryType.EPISODIC, source=MemorySource.BROWSER,
            importance=0.35, expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

    def index_project(self, root: str, name: str | None = None):
        project = self.projects.index(root, name)
        self.working.update(active_project=project.id)
        description = f"Proyecto {project.name} en {project.root_path}. Tecnologías: {', '.join(project.technologies) or 'no detectadas'}."
        self.remember(description, MemoryType.PROJECT, source=MemorySource.PROJECT, project_id=project.id, key=f"{project.id}:overview")
        return project

    def last_session(self) -> str:
        conversation = self.repository.latest_conversation()
        if not conversation:
            return "No hay una sesión anterior guardada."
        return conversation.summary or "La sesión anterior no tiene resumen todavía."
