from __future__ import annotations

import json
from dataclasses import astuple
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from app.users.models import UserPermission, UserPreference, UserProfile, UserRole, VoiceProfile
from app.users.session import UserSession


LEGACY_OWNER_ID = str(uuid5(NAMESPACE_URL, "jarvis:legacy-owner"))


def _now() -> datetime: return datetime.now(timezone.utc)
def _iso(value: datetime) -> str: return value.isoformat()
def _date(value: str) -> datetime: return datetime.fromisoformat(value.replace("Z", "+00:00"))


class UserRepository:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True); self._migrate()

    def _conn(self):
        connection = sqlite3.connect(self.path); connection.row_factory = sqlite3.Row; return connection

    def _migrate(self) -> None:
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, display_name TEXT NOT NULL COLLATE NOCASE UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, language TEXT NOT NULL, timezone TEXT NOT NULL, response_style TEXT NOT NULL, preferred_voice TEXT, default_project_id TEXT, default_iot_device_id TEXT, role TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, avatar_url TEXT, password_hash TEXT, failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT);
            CREATE TABLE IF NOT EXISTS user_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, started_at TEXT NOT NULL, last_activity_at TEXT NOT NULL, authenticated INTEGER NOT NULL, locked INTEGER NOT NULL DEFAULT 0, ended_at TEXT, FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS user_preferences (user_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(user_id,key), FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS user_permissions (user_id TEXT NOT NULL, capability TEXT NOT NULL, allowed INTEGER NOT NULL, max_security_level TEXT NOT NULL, PRIMARY KEY(user_id,capability), FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS user_voice_profiles (user_id TEXT PRIMARY KEY, tts_voice TEXT NOT NULL, speech_rate REAL NOT NULL, volume REAL NOT NULL, language TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS user_device_permissions (user_id TEXT NOT NULL, device_id TEXT NOT NULL, access_level TEXT NOT NULL, PRIMARY KEY(user_id,device_id));
            CREATE TABLE IF NOT EXISTS user_integrations (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, provider TEXT NOT NULL, account_label TEXT NOT NULL, credentials_path TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', UNIQUE(user_id,provider,account_label));
            """)
            if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
                now = _now(); c.execute("INSERT INTO users(id,display_name,created_at,updated_at,language,timezone,response_style,role,enabled) VALUES(?,?,?,?,?,?,?,?,1)", (LEGACY_OWNER_ID, "Owner", _iso(now), _iso(now), "es", "America/Guayaquil", "technical", UserRole.OWNER.value))

    def _profile(self, row) -> UserProfile:
        return UserProfile(row["id"], row["display_name"], _date(row["created_at"]), _date(row["updated_at"]), row["language"], row["timezone"], row["response_style"], row["preferred_voice"], row["default_project_id"], row["default_iot_device_id"], UserRole(row["role"]), bool(row["enabled"]), row["avatar_url"])
    def create(self, display_name: str, *, role: UserRole = UserRole.STANDARD, language="es", timezone="America/Guayaquil", password_hash: str | None = None) -> UserProfile:
        from uuid import uuid4
        now = _now(); user = UserProfile(str(uuid4()), display_name.strip(), now, now, language, timezone, "technical", None, None, None, role, True)
        values = list(astuple(user)); values[2] = _iso(user.created_at); values[3] = _iso(user.updated_at); values[10] = user.role.value
        with self._conn() as c: c.execute("INSERT INTO users(id,display_name,created_at,updated_at,language,timezone,response_style,preferred_voice,default_project_id,default_iot_device_id,role,enabled,avatar_url,password_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (*values, password_hash))
        return user
    def get(self, user_id: str) -> UserProfile | None:
        with self._conn() as c: row=c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return self._profile(row) if row else None
    def get_by_name(self, name: str) -> UserProfile | None:
        with self._conn() as c: row=c.execute("SELECT * FROM users WHERE display_name=? COLLATE NOCASE", (name.strip(),)).fetchone()
        return self._profile(row) if row else None
    def list(self, *, enabled_only=False) -> list[UserProfile]:
        query="SELECT * FROM users" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY display_name"
        with self._conn() as c: return [self._profile(row) for row in c.execute(query)]
    def update(self, user_id: str, **changes) -> UserProfile | None:
        allowed={"display_name","language","timezone","response_style","preferred_voice","default_project_id","default_iot_device_id","avatar_url","role","enabled"}; changes={key:(value.value if isinstance(value,UserRole) else value) for key,value in changes.items() if key in allowed and value is not None}
        if not changes: return self.get(user_id)
        changes["updated_at"]=_iso(_now()); fields=", ".join(f"{key}=?" for key in changes)
        with self._conn() as c: c.execute(f"UPDATE users SET {fields} WHERE id=?", (*changes.values(),user_id))
        return self.get(user_id)
    def disable(self, user_id: str) -> bool:
        return self.update(user_id, enabled=False) is not None
    def password_hash(self, user_id: str) -> str | None:
        with self._conn() as c: row=c.execute("SELECT password_hash FROM users WHERE id=?",(user_id,)).fetchone()
        return row[0] if row else None
    def set_preference(self, user_id,key,value):
        now=_iso(_now())
        with self._conn() as c: c.execute("INSERT INTO user_preferences(user_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(user_id,key,str(value),now))
    def preferences(self,user_id):
        with self._conn() as c: return {r["key"]:r["value"] for r in c.execute("SELECT key,value FROM user_preferences WHERE user_id=?",(user_id,))}
    def set_voice(self, voice: VoiceProfile):
        with self._conn() as c: c.execute("INSERT INTO user_voice_profiles VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET tts_voice=excluded.tts_voice,speech_rate=excluded.speech_rate,volume=excluded.volume,language=excluded.language", astuple(voice))
    def voice(self,user_id):
        with self._conn() as c: row=c.execute("SELECT * FROM user_voice_profiles WHERE user_id=?",(user_id,)).fetchone()
        return VoiceProfile(**dict(row)) if row else None
    def save_session(self, session: UserSession):
        with self._conn() as c: c.execute("INSERT INTO user_sessions(id,user_id,started_at,last_activity_at,authenticated,locked,ended_at) VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET last_activity_at=excluded.last_activity_at,authenticated=excluded.authenticated,locked=excluded.locked,ended_at=NULL",(session.id,session.user_id,_iso(session.started_at),_iso(session.last_activity_at),int(session.authenticated),int(session.locked)))
    def close_session(self, session_id):
        with self._conn() as c: c.execute("UPDATE user_sessions SET ended_at=? WHERE id=?",(_iso(_now()),session_id))
    def active_session(self):
        with self._conn() as c: row=c.execute("SELECT * FROM user_sessions WHERE ended_at IS NULL ORDER BY last_activity_at DESC LIMIT 1").fetchone()
        return UserSession(row["id"],row["user_id"],_date(row["started_at"]),_date(row["last_activity_at"]),bool(row["authenticated"]),bool(row["locked"])) if row else None
