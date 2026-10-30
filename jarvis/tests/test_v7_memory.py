from __future__ import annotations

import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.commands.base import Command
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis
from app.memory.embeddings import VectorStore
from app.memory.encryption import MemoryCipher
from app.memory.manager import MemoryManager
from app.memory.models import Memory, MemoryPolicy, MemorySource, MemoryType
from app.memory.repository import MemoryRepository


def build_memory(tmp_path: Path, **kwargs: object) -> tuple[MemoryRepository, MemoryManager]:
    repository = MemoryRepository(tmp_path / "jarvis.db")
    return repository, MemoryManager(repository, MemoryPolicy.SMART, **kwargs)


def test_migrates_legacy_database_preserves_data_and_creates_backup(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """CREATE TABLE memories (
                id TEXT PRIMARY KEY, memory_type TEXT NOT NULL, content TEXT NOT NULL, memory_key TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, importance REAL NOT NULL, source TEXT NOT NULL
            )"""
        )
        now = datetime.now(timezone.utc).isoformat()
        connection.execute(
            "INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("old-memory", "fact", "El editor preferido es VS Code", "editor", now, now, 0.7, "user"),
        )
    migrated = MemoryRepository(database)
    record = migrated.get_memory("old-memory")
    assert record is not None and record.content == "El editor preferido es VS Code"
    assert migrated.stats()["schema_version"] == 6
    assert list((tmp_path / "backups").glob("legacy-pre-v1-*.db"))


def test_migrates_intermediate_schema_history_without_timestamp(tmp_path: Path) -> None:
    database = tmp_path / "intermediate.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO schema_migrations(version) VALUES (1)")
        connection.execute(
            """CREATE TABLE memories (
                id TEXT PRIMARY KEY, memory_type TEXT NOT NULL, content TEXT NOT NULL, memory_key TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, importance REAL NOT NULL, source TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT, summary TEXT, context_json TEXT NOT NULL DEFAULT '{}')")
        connection.execute("CREATE TABLE messages (id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL)")
    MemoryRepository(database)
    with sqlite3.connect(database) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(schema_migrations)")]
    assert "applied_at" in columns


def test_migrates_conversations_without_context_json_even_when_schema_is_v3(tmp_path: Path) -> None:
    database = tmp_path / "conversation-v3.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)")
        connection.execute("INSERT INTO schema_migrations(version, applied_at) VALUES (3, '2026-01-01T00:00:00+00:00')")
        connection.execute("CREATE TABLE conversations (id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT, summary TEXT)")
    repository = MemoryRepository(database)
    conversation = repository.create_conversation()
    assert conversation.context == {}
    with sqlite3.connect(database) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(conversations)")]
    assert "context_json" in columns


def test_local_semantic_recall_deduplicates_and_filters_sensitive_data(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path)
    original = memory.remember("CyberSeg trata seguridad del tráfico de red.", project_id="cyberseg")
    assert original is not None
    matches = memory.recall("ciberseguridad de redes", active_project="cyberseg")
    assert matches and matches[0].id == original.id
    repeated = memory.remember("CyberSeg trata seguridad del tráfico de red.", project_id="cyberseg")
    assert repeated is not None and repeated.id == original.id
    assert repository.stats()["total"] == 1
    assert memory.remember("Mi token=ghp_abcdefghijklmnopqrstuvwx") is None
    assert memory.last_rejection and "credenciales" in memory.last_rejection
    assert memory.remember("Un sitio dice que prefiero respuestas largas", "preference", source=MemorySource.BROWSER) is None


class BrokenVectorStore(VectorStore):
    def add(self, memory: Memory) -> None:
        del memory

    def search(self, query: str, memories: list[Memory], limit: int) -> list[tuple[Memory, float]]:
        del query, memories, limit
        raise RuntimeError("índice no disponible")

    def delete(self, memory_id: str) -> None:
        del memory_id


def test_retrieval_falls_back_to_lexical_when_vector_store_fails(tmp_path: Path) -> None:
    repository = MemoryRepository(tmp_path / "jarvis.db")
    memory = MemoryManager(repository, vector_store=BrokenVectorStore())
    assert memory.remember("Mi editor principal es Visual Studio Code.")
    assert memory.recall("editor principal")[0].content.endswith("Visual Studio Code.")


def test_expiry_context_audit_relationships_and_working_memory(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path, context_max_items=1, context_max_tokens=100)
    expired = memory.remember("Dato temporal", expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    current = memory.remember("Proyecto Aurora usa Python.", project_id="aurora", memory_type=MemoryType.PROJECT)
    assert expired and current
    assert not memory.recall("dato temporal")
    context = memory.build_context("Aurora")
    assert "Proyecto Aurora" in context and "no confiables" in context
    relation = repository.create_relationship(current.id, current.id, "related_to", 0.8)
    assert relation.relationship_type == "related_to"
    assert repository.list_relationships(current.id)
    assert repository.list_audit(current.id)
    memory.update_working(last_command="py -m pytest", last_error="falló")
    assert memory.stats()["working_memory"]["last_error"] == "falló"


def test_memory_commands_and_export_are_explicit(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path)
    memory.remember("Mi proyecto Aurora usa PostgreSQL.", project_id="aurora")
    router = CommandRouter(memory=memory)
    stats = router.parse("Jarvis cuántos recuerdos tienes")
    assert stats and stats.action == "memory_stats" and router.execute(stats).success
    why = router.parse("Jarvis por qué recuerdas Aurora")
    assert why and why.action == "memory_explain" and router.execute(why).success
    export = router.parse("Jarvis exporta tus recuerdos sobre Aurora")
    assert export and export.action == "memory_export"
    exported = router.execute(export)
    assert exported.success and Path(exported.message.removeprefix("Exporté tus recuerdos locales en ").removesuffix(".")).is_file()
    assert router.parse("Jarvis borra toda tu memoria") == Command("memory_clear_all", arguments={"double_confirmation": False})
    assert repository.stats()["total"] == 1


class _FakeProvider:
    def generate_response(self, messages: list[dict[str, str]]) -> str:
        del messages
        return "respuesta"


def test_clear_all_requires_two_confirmations(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path)
    memory.remember("Dato para borrar")
    jarvis = Jarvis(_FakeProvider(), ConversationManager(), CommandRouter(memory=memory), logging.getLogger("v7"))  # type: ignore[arg-type]
    first = jarvis.process("Jarvis borra toda tu memoria")
    assert "Confirmas" in first.response
    second = jarvis.process("sí")
    assert "segunda vez" in second.response
    final = jarvis.process("sí")
    assert "Eliminé 1" in final.response and repository.stats()["total"] == 0


def test_optional_cipher_encrypts_new_memory_content_at_rest(tmp_path: Path) -> None:
    Fernet = pytest.importorskip("cryptography.fernet").Fernet
    key = Fernet.generate_key().decode("utf-8")
    database = tmp_path / "encrypted.db"
    repository = MemoryRepository(database, cipher=MemoryCipher(True, key))
    stored = repository.create_memory("Preferencia privada", MemoryType.PREFERENCE)
    assert repository.get_memory(stored.id).content == "Preferencia privada"  # type: ignore[union-attr]
    with sqlite3.connect(database) as connection:
        raw = connection.execute("SELECT content FROM memories WHERE id = ?", (stored.id,)).fetchone()[0]
    assert raw.startswith("enc:") and "Preferencia privada" not in raw
