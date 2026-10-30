"""Persistencia SQLite y migraciones compatibles para la memoria de JARVIS."""

from __future__ import annotations

import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from app.memory.models import (
    Conversation,
    Memory,
    MemoryAuditEntry,
    MemoryRelationship,
    MemorySource,
    MemoryType,
    ProjectMemory,
    StoredMessage,
)
from app.memory.encryption import MemoryCipher


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return value.astimezone(timezone.utc).isoformat()


def _from_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _enum_or_raw(enum_type: type[MemoryType] | type[MemorySource], value: str):
    """Mantiene valores heredados que no existían en el enum de v0.7."""
    try:
        return enum_type(value)
    except ValueError:
        return value


def _value(value: Any) -> str:
    return value.value if isinstance(value, (MemoryType, MemorySource)) else str(value)


class MemoryRepository:
    """Repositorio local con migración no destructiva desde el esquema v0.6."""

    SCHEMA_VERSION = 6

    def __init__(self, path: str | Path, cipher: MemoryCipher | None = None) -> None:
        self.path = Path(path)
        self._cipher = cipher or MemoryCipher()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _migrate(self) -> None:
        existed = self.path.exists() and self.path.stat().st_size > 0
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            # Algunas compilaciones previas registraron solo la versión. Se amplía
            # ese historial antes de insertar fechas, sin reconstruir ni borrar tablas.
            if not self._has_column(connection, "schema_migrations", "applied_at"):
                connection.execute("ALTER TABLE schema_migrations ADD COLUMN applied_at TEXT")
                connection.execute(
                    "UPDATE schema_migrations SET applied_at = ? WHERE applied_at IS NULL",
                    (_as_iso(_utcnow()),),
                )
            current_row = connection.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
            current = int(current_row["version"] or 0)
            if current == 0:
                self._create_v1_tables(connection)
                connection.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (1, _as_iso(_utcnow())),
                )
                current = 1

            if existed and current < self.SCHEMA_VERSION:
                self._backup_before_migration(current)

            if current < 2:
                self._migrate_v2(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (2, _as_iso(_utcnow())),
                )
                current = 2
            if current < 3:
                self._migrate_v3(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (3, _as_iso(_utcnow())),
                )
                current = 3
            if current < 4:
                self._migrate_v4(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (4, _as_iso(_utcnow())),
                )
                current = 4
            if current < 5:
                self._migrate_v5(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (5, _as_iso(_utcnow())),
                )
                current = 5
            if current < 6:
                self._migrate_v6(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (6, _as_iso(_utcnow())),
                )
                current = 6
            # v1.4 ownership is additive and deliberately lives outside the
            # historical Memory Engine version sequence for compatibility.
            self._migrate_v7(connection)

    def _backup_before_migration(self, current: int) -> Path:
        backup_dir = self.path.parent / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = _utcnow().strftime("%Y%m%dT%H%M%SZ")
        backup = backup_dir / f"{self.path.stem}-pre-v{current}-{stamp}{self.path.suffix}"
        shutil.copy2(self.path, backup)
        return backup

    @staticmethod
    def _create_v1_tables(connection: sqlite3.Connection) -> None:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                memory_type TEXT NOT NULL,
                content TEXT NOT NULL,
                memory_key TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                importance REAL NOT NULL DEFAULT 0.5,
                source TEXT NOT NULL DEFAULT 'user'
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(memory_type)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(memory_key)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                summary TEXT,
                context_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at)")

    @staticmethod
    def _has_column(connection: sqlite3.Connection, table: str, column: str) -> bool:
        return column in {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}

    def _migrate_v2(self, connection: sqlite3.Connection) -> None:
        additions = {
            "confidence": "REAL NOT NULL DEFAULT 1.0",
            "project_id": "TEXT",
            "expires_at": "TEXT",
            "last_accessed_at": "TEXT",
            "embedding_id": "TEXT",
        }
        for column, definition in additions.items():
            if not self._has_column(connection, "memories", column):
                connection.execute(f"ALTER TABLE memories ADD COLUMN {column} {definition}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_memories_project ON memories(project_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_memories_expiry ON memories(expires_at)")

    @staticmethod
    def _migrate_v3(connection: sqlite3.Connection) -> None:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS memory_embeddings (
                memory_id TEXT PRIMARY KEY,
                vector_json TEXT NOT NULL,
                embedding_model TEXT NOT NULL,
                embedding_version TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(memory_id) REFERENCES memories(id) ON DELETE CASCADE
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS memory_relationships (
                id TEXT PRIMARY KEY,
                source_memory_id TEXT NOT NULL,
                target_memory_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 1.0,
                created_at TEXT NOT NULL,
                UNIQUE(source_memory_id, target_memory_id, relationship_type),
                FOREIGN KEY(source_memory_id) REFERENCES memories(id) ON DELETE CASCADE,
                FOREIGN KEY(target_memory_id) REFERENCES memories(id) ON DELETE CASCADE
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                root_path TEXT NOT NULL,
                technologies_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS memory_audit (
                id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                memory_id TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_memory ON memory_audit(memory_id, created_at)")

    def _migrate_v4(self, connection: sqlite3.Connection) -> None:
        """Repara conversaciones creadas antes de que el contexto fuese persistente."""
        if not self._has_column(connection, "conversations", "context_json"):
            connection.execute("ALTER TABLE conversations ADD COLUMN context_json TEXT NOT NULL DEFAULT '{}'")

    @staticmethod
    def _migrate_v5(connection: sqlite3.Connection) -> None:
        """Añade el almacenamiento local IoT v0.9 sin alterar recuerdos existentes."""
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_devices (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, device_type TEXT NOT NULL, status TEXT NOT NULL,
                last_seen TEXT, capabilities_json TEXT NOT NULL DEFAULT '[]', telemetry_topics_json TEXT NOT NULL DEFAULT '[]',
                command_topics_json TEXT NOT NULL DEFAULT '[]', trusted INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL DEFAULT '{}', state_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_iot_devices_name ON iot_devices(name COLLATE NOCASE)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_topics (
                name TEXT PRIMARY KEY, direction TEXT NOT NULL, device_id TEXT NOT NULL, purpose TEXT NOT NULL,
                qos INTEGER NOT NULL DEFAULT 1, retain INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_topics_device ON iot_topics(device_id)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_telemetry (
                id TEXT PRIMARY KEY, device_id TEXT NOT NULL, sensor TEXT NOT NULL, value_json TEXT NOT NULL,
                unit TEXT, timestamp TEXT NOT NULL, FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_telemetry_query ON iot_telemetry(device_id, sensor, timestamp DESC)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_rules (
                id TEXT PRIMARY KEY, device_id TEXT NOT NULL, sensor TEXT NOT NULL, operator TEXT NOT NULL,
                threshold REAL NOT NULL, action TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL, last_triggered_at TEXT,
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_rules_active ON iot_rules(device_id, sensor, enabled)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_command_history (
                request_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, command TEXT NOT NULL, sent_at TEXT NOT NULL,
                acknowledged_at TEXT, status TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(device_id) REFERENCES iot_devices(id) ON DELETE CASCADE
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_iot_commands_status ON iot_command_history(status, sent_at)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS iot_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, device_id TEXT,
                details_json TEXT NOT NULL DEFAULT '{}', occurred_at TEXT NOT NULL
            )"""
        )

    @staticmethod
    def _migrate_v6(connection: sqlite3.Connection) -> None:
        """Automatizaciones v1.0 persistentes, sin tocar memoria, tareas ni telemetría."""
        connection.execute(
            """CREATE TABLE IF NOT EXISTS automations (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, trigger_json TEXT NOT NULL, conditions_json TEXT NOT NULL,
                actions_json TEXT NOT NULL, enabled INTEGER NOT NULL, priority TEXT NOT NULL, policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL, last_run_at TEXT
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_automations_enabled ON automations(enabled)")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS automation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, automation_id TEXT NOT NULL, started_at TEXT NOT NULL,
                completed_at TEXT, status TEXT NOT NULL, summary TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_automation_history ON automation_history(automation_id, started_at DESC)")

    @staticmethod
    def _migrate_v7(connection: sqlite3.Connection) -> None:
        """v1.4: add scoped ownership without deleting legacy records."""
        from app.users.repository import LEGACY_OWNER_ID
        tables = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "memories" not in tables:
            return
        additions = {"user_id": "TEXT", "scope": "TEXT NOT NULL DEFAULT 'private'"}
        for column, definition in additions.items():
            if not MemoryRepository._has_column(connection, "memories", column):
                connection.execute(f"ALTER TABLE memories ADD COLUMN {column} {definition}")
        if "conversations" in tables and not MemoryRepository._has_column(connection, "conversations", "user_id"):
            connection.execute("ALTER TABLE conversations ADD COLUMN user_id TEXT")
        if "projects" in tables and not MemoryRepository._has_column(connection, "projects", "user_id"):
            connection.execute("ALTER TABLE projects ADD COLUMN user_id TEXT")
        connection.execute("UPDATE memories SET user_id=? WHERE user_id IS NULL", (LEGACY_OWNER_ID,))
        if "conversations" in tables: connection.execute("UPDATE conversations SET user_id=? WHERE user_id IS NULL", (LEGACY_OWNER_ID,))
        if "projects" in tables: connection.execute("UPDATE projects SET user_id=? WHERE user_id IS NULL", (LEGACY_OWNER_ID,))
        connection.execute("CREATE INDEX IF NOT EXISTS idx_memories_user_scope ON memories(user_id, scope, updated_at DESC)")

    def _memory_from_row(self, row: sqlite3.Row) -> Memory:
        row_keys = set(row.keys())
        return Memory(
            id=row["id"],
            memory_type=_enum_or_raw(MemoryType, row["memory_type"]),
            content=self._cipher.decrypt(row["content"]),
            key=row["memory_key"],
            created_at=_from_iso(row["created_at"]) or _utcnow(),
            updated_at=_from_iso(row["updated_at"]) or _utcnow(),
            importance=float(row["importance"]),
            source=_enum_or_raw(MemorySource, row["source"]),
            confidence=float(row["confidence"]) if "confidence" in row_keys else 1.0,
            project_id=row["project_id"] if "project_id" in row_keys else None,
            expires_at=_from_iso(row["expires_at"]) if "expires_at" in row_keys else None,
            last_accessed_at=_from_iso(row["last_accessed_at"]) if "last_accessed_at" in row_keys else None,
            embedding_id=row["embedding_id"] if "embedding_id" in row_keys else None,
            user_id=row["user_id"] if "user_id" in row_keys else None,
            scope=row["scope"] if "scope" in row_keys else "private",
        )

    def _conversation_from_row(self, row: sqlite3.Row) -> Conversation:
        return Conversation(
            id=row["id"],
            started_at=_from_iso(row["started_at"]) or _utcnow(),
            ended_at=_from_iso(row["ended_at"]),
            summary=self._cipher.decrypt(row["summary"]) if row["summary"] else None,
            context=json.loads(row["context_json"] or "{}"),
        )

    def create_memory(
        self,
        content: str,
        memory_type: MemoryType | str = MemoryType.SEMANTIC,
        *,
        key: str | None = None,
        importance: float = 0.5,
        source: MemorySource | str = MemorySource.USER,
        confidence: float = 1.0,
        project_id: str | None = None,
        expires_at: datetime | str | None = None,
        embedding_id: str | None = None,
        user_id: str | None = None,
        scope: str = "private",
    ) -> Memory:
        now = _utcnow()
        memory = Memory(
            id=str(uuid4()),
            memory_type=memory_type,
            content=content,
            key=key,
            created_at=now,
            updated_at=now,
            importance=max(0.0, min(1.0, importance)),
            source=source,
            confidence=max(0.0, min(1.0, confidence)),
            project_id=project_id,
            expires_at=_from_iso(_as_iso(expires_at)),
            embedding_id=embedding_id,
            user_id=user_id,
            scope=scope,
        )
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO memories (
                    id, memory_type, content, memory_key, created_at, updated_at, importance, source,
                    confidence, project_id, expires_at, last_accessed_at, embedding_id, user_id, scope
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    memory.id,
                    _value(memory.memory_type),
                    self._cipher.encrypt(memory.content),
                    memory.key,
                    _as_iso(memory.created_at),
                    _as_iso(memory.updated_at),
                    memory.importance,
                    _value(memory.source),
                    memory.confidence,
                    memory.project_id,
                    _as_iso(memory.expires_at),
                    None,
                    memory.embedding_id,
                    memory.user_id,
                    str(memory.scope.value if hasattr(memory.scope, "value") else memory.scope),
                ),
            )
        return memory

    def get_memory(self, memory_id: str, *, include_expired: bool = True) -> Memory | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM memories WHERE id = ?", (memory_id,)).fetchone()
        if row is None:
            return None
        memory = self._memory_from_row(row)
        if not include_expired and memory.expires_at and memory.expires_at <= _utcnow():
            return None
        return memory

    def list_memories(
        self,
        *,
        memory_type: MemoryType | str | None = None,
        project_id: str | None = None,
        user_id: str | None = None,
        include_shared: bool = True,
        include_expired: bool = False,
        limit: int | None = None,
    ) -> list[Memory]:
        clauses: list[str] = []
        params: list[Any] = []
        if memory_type:
            clauses.append("memory_type = ?")
            params.append(_value(memory_type))
        if project_id:
            clauses.append("project_id = ?")
            params.append(project_id)
        if user_id is not None:
            clauses.append("(user_id = ? OR (scope IN ('shared', 'system') AND ?))" if include_shared else "user_id = ?")
            params.append(user_id)
            if include_shared: params.append(1)
        if not include_expired:
            clauses.append("(expires_at IS NULL OR expires_at > ?)")
            params.append(_as_iso(_utcnow()))
        sql = "SELECT * FROM memories"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY updated_at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        with self._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._memory_from_row(row) for row in rows]

    def find_by_key(self, key: str, *, project_id: str | None = None, user_id: str | None = None) -> Memory | None:
        clauses = ["memory_key = ?"]
        params: list[Any] = [key]
        if project_id is not None:
            clauses.append("project_id = ?")
            params.append(project_id)
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM memories WHERE " + " AND ".join(clauses) + " ORDER BY updated_at DESC LIMIT 1",
                params,
            ).fetchone()
        return self._memory_from_row(row) if row else None

    def update_memory(self, memory_id: str, content: str | None = None, **changes: Any) -> Memory | None:
        """Actualiza metadatos; el segundo argumento posicional conserva la API v0.6."""
        if content is not None:
            changes["content"] = content
        allowed = {
            "content": "content",
            "memory_type": "memory_type",
            "key": "memory_key",
            "importance": "importance",
            "source": "source",
            "confidence": "confidence",
            "project_id": "project_id",
            "expires_at": "expires_at",
            "last_accessed_at": "last_accessed_at",
            "embedding_id": "embedding_id",
        }
        fields: list[str] = []
        params: list[Any] = []
        for name, column in allowed.items():
            if name not in changes:
                continue
            value = changes[name]
            if name == "content" and value is not None:
                value = self._cipher.encrypt(str(value))
            if name in {"expires_at", "last_accessed_at"}:
                value = _as_iso(value)
            elif name in {"memory_type", "source"}:
                value = _value(value)
            elif name in {"importance", "confidence"} and value is not None:
                value = max(0.0, min(1.0, float(value)))
            fields.append(f"{column} = ?")
            params.append(value)
        if not fields:
            return self.get_memory(memory_id)
        fields.append("updated_at = ?")
        params.append(_as_iso(_utcnow()))
        params.append(memory_id)
        with self._connection() as connection:
            connection.execute("UPDATE memories SET " + ", ".join(fields) + " WHERE id = ?", params)
        return self.get_memory(memory_id)

    def touch_memory(self, memory_id: str) -> None:
        self.update_memory(memory_id, last_accessed_at=_utcnow())

    def delete_memory(self, memory_id: str) -> bool:
        with self._connection() as connection:
            cursor = connection.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        return cursor.rowcount > 0

    def delete_all_memories(self) -> int:
        with self._connection() as connection:
            count = int(connection.execute("SELECT COUNT(*) AS count FROM memories").fetchone()["count"])
            connection.execute("DELETE FROM memories")
        return count

    def purge_expired(self) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ?", (_as_iso(_utcnow()),)
            )
        return cursor.rowcount

    def set_embedding(
        self, memory_id: str, vector: Iterable[float], *, model: str, version: str = "1"
    ) -> None:
        now = _as_iso(_utcnow())
        vector_json = json.dumps([float(item) for item in vector])
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO memory_embeddings(memory_id, vector_json, embedding_model, embedding_version, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(memory_id) DO UPDATE SET vector_json=excluded.vector_json,
                    embedding_model=excluded.embedding_model, embedding_version=excluded.embedding_version,
                    updated_at=excluded.updated_at""",
                (memory_id, vector_json, model, version, now),
            )
            connection.execute("UPDATE memories SET embedding_id = ?, updated_at = ? WHERE id = ?", (memory_id, now, memory_id))

    def get_embeddings(self) -> dict[str, list[float]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT memory_id, vector_json FROM memory_embeddings").fetchall()
        return {row["memory_id"]: [float(value) for value in json.loads(row["vector_json"])] for row in rows}

    def delete_embedding(self, memory_id: str) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM memory_embeddings WHERE memory_id = ?", (memory_id,))

    def create_relationship(
        self,
        source_memory_id: str,
        target_memory_id: str,
        relationship_type: str,
        confidence: float = 1.0,
    ) -> MemoryRelationship:
        relation = MemoryRelationship(
            id=str(uuid4()),
            source_memory_id=source_memory_id,
            target_memory_id=target_memory_id,
            relationship_type=relationship_type,
            confidence=max(0.0, min(1.0, confidence)),
            created_at=_utcnow(),
        )
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO memory_relationships(
                    id, source_memory_id, target_memory_id, relationship_type, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_memory_id, target_memory_id, relationship_type)
                DO UPDATE SET confidence=excluded.confidence""",
                (
                    relation.id,
                    relation.source_memory_id,
                    relation.target_memory_id,
                    relation.relationship_type,
                    relation.confidence,
                    _as_iso(relation.created_at),
                ),
            )
        return relation

    def list_relationships(self, memory_id: str) -> list[MemoryRelationship]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM memory_relationships WHERE source_memory_id = ? OR target_memory_id = ?",
                (memory_id, memory_id),
            ).fetchall()
        return [
            MemoryRelationship(
                id=row["id"],
                source_memory_id=row["source_memory_id"],
                target_memory_id=row["target_memory_id"],
                relationship_type=row["relationship_type"],
                confidence=float(row["confidence"]),
                created_at=_from_iso(row["created_at"]) or _utcnow(),
            )
            for row in rows
        ]

    def upsert_project(self, project: ProjectMemory) -> ProjectMemory:
        now = _utcnow()
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO projects(id, name, root_path, technologies_json, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, root_path=excluded.root_path,
                    technologies_json=excluded.technologies_json, metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at""",
                (
                    project.id,
                    project.name,
                    project.root_path,
                    json.dumps(list(project.technologies)),
                    json.dumps(project.metadata),
                    _as_iso(project.created_at),
                    _as_iso(now),
                ),
            )
        return ProjectMemory(
            id=project.id,
            name=project.name,
            root_path=project.root_path,
            technologies=project.technologies,
            metadata=project.metadata,
            created_at=project.created_at,
            updated_at=now,
        )

    def get_project(self, project_id: str) -> ProjectMemory | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        return self._project_from_row(row) if row else None

    def list_projects(self) -> list[ProjectMemory]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()
        return [self._project_from_row(row) for row in rows]

    @staticmethod
    def _project_from_row(row: sqlite3.Row) -> ProjectMemory:
        return ProjectMemory(
            id=row["id"],
            name=row["name"],
            root_path=row["root_path"],
            technologies=tuple(json.loads(row["technologies_json"] or "[]")),
            metadata=json.loads(row["metadata_json"] or "{}"),
            created_at=_from_iso(row["created_at"]) or _utcnow(),
            updated_at=_from_iso(row["updated_at"]) or _utcnow(),
        )

    def log_audit(self, action: str, *, memory_id: str | None = None, details: dict[str, Any] | None = None) -> MemoryAuditEntry:
        audit = MemoryAuditEntry(
            id=str(uuid4()), action=action, memory_id=memory_id, details=details or {}, created_at=_utcnow()
        )
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO memory_audit(id, action, memory_id, details_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (audit.id, audit.action, audit.memory_id, json.dumps(audit.details), _as_iso(audit.created_at)),
            )
        return audit

    def list_audit(self, memory_id: str | None = None, *, limit: int = 50) -> list[MemoryAuditEntry]:
        sql = "SELECT * FROM memory_audit"
        params: list[Any] = []
        if memory_id:
            sql += " WHERE memory_id = ?"
            params.append(memory_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [
            MemoryAuditEntry(
                id=row["id"],
                action=row["action"],
                memory_id=row["memory_id"],
                details=json.loads(row["details_json"] or "{}"),
                created_at=_from_iso(row["created_at"]) or _utcnow(),
            )
            for row in rows
        ]

    def create_conversation(self, context: dict[str, Any] | None = None) -> Conversation:
        conversation = Conversation(id=str(uuid4()), started_at=_utcnow(), context=context or {})
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO conversations(id, started_at, ended_at, summary, context_json) VALUES (?, ?, NULL, NULL, ?)",
                (conversation.id, _as_iso(conversation.started_at), json.dumps(conversation.context)),
            )
        return conversation

    def get_conversation(self, conversation_id: str) -> Conversation | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        return self._conversation_from_row(row) if row else None

    def latest_conversation(self) -> Conversation | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM conversations ORDER BY started_at DESC LIMIT 1").fetchone()
        return self._conversation_from_row(row) if row else None

    def finish_conversation(self, conversation_id: str, summary: str | None = None) -> Conversation | None:
        with self._connection() as connection:
            connection.execute(
                "UPDATE conversations SET ended_at = ?, summary = ? WHERE id = ?",
                (_as_iso(_utcnow()), self._cipher.encrypt(summary) if summary else None, conversation_id),
            )
        return self.get_conversation(conversation_id)

    def add_message(self, conversation_id: str, role: str, content: str) -> StoredMessage:
        message = StoredMessage(id=str(uuid4()), conversation_id=conversation_id, role=role, content=content, created_at=_utcnow())
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO messages(id, conversation_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)",
                (message.id, message.conversation_id, message.role, self._cipher.encrypt(message.content), _as_iso(message.created_at)),
            )
        return message

    def list_messages(self, conversation_id: str, *, limit: int | None = None) -> list[StoredMessage]:
        sql = "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC"
        params: list[Any] = [conversation_id]
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        with self._connection() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [
            StoredMessage(
                id=row["id"],
                conversation_id=row["conversation_id"],
                role=row["role"],
                content=self._cipher.decrypt(row["content"]),
                created_at=_from_iso(row["created_at"]) or _utcnow(),
            )
            for row in rows
        ]

    def backup_to(self, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as source, sqlite3.connect(target) as backup:
            source.backup(backup)
        return target

    def restore_from(self, source: str | Path) -> None:
        source_path = Path(source)
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        self._backup_before_migration(self.SCHEMA_VERSION)
        shutil.copy2(source_path, self.path)
        self._migrate()

    def stats(self) -> dict[str, Any]:
        with self._connection() as connection:
            total = int(connection.execute("SELECT COUNT(*) AS count FROM memories").fetchone()["count"])
            rows = connection.execute("SELECT memory_type, COUNT(*) AS count FROM memories GROUP BY memory_type").fetchall()
            vectors = int(connection.execute("SELECT COUNT(*) AS count FROM memory_embeddings").fetchone()["count"])
            relationships = int(connection.execute("SELECT COUNT(*) AS count FROM memory_relationships").fetchone()["count"])
        return {
            "total": total,
            "by_type": {row["memory_type"]: int(row["count"]) for row in rows},
            "vectors": vectors,
            "relationships": relationships,
            "schema_version": self.SCHEMA_VERSION,
        }
