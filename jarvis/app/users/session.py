from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from uuid import uuid4


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class UserSession:
    id: str
    user_id: str
    started_at: datetime
    last_activity_at: datetime
    authenticated: bool
    locked: bool = False


class SessionManager:
    def __init__(self, repository, on_switch=None, on_lock=None) -> None:
        self.repository, self.on_switch, self.on_lock = repository, on_switch, on_lock
        self._session: UserSession | None = repository.active_session()

    def start_session(self, user_id: str, *, authenticated: bool) -> UserSession:
        if self._session:
            self.end_session()
        now = _now()
        self._session = UserSession(str(uuid4()), user_id, now, now, authenticated)
        self.repository.save_session(self._session)
        if self.on_switch:
            self.on_switch(user_id)
        return self._session

    def end_session(self) -> None:
        if self._session:
            self.repository.close_session(self._session.id)
        self._session = None

    def switch_user(self, user_id: str, *, authenticated: bool) -> UserSession:
        return self.start_session(user_id, authenticated=authenticated)

    def get_active_user_id(self) -> str | None:
        return self._session.user_id if self._session and not self._session.locked else None

    def lock_session(self) -> None:
        if not self._session:
            return
        self._session = replace(self._session, locked=True, last_activity_at=_now())
        self.repository.save_session(self._session)
        if self.on_lock:
            self.on_lock()
