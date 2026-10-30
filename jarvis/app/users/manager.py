from __future__ import annotations

from app.users.models import UserContext, UserRole, VoiceProfile
from app.users.permissions import ROLE_PERMISSIONS, role_allows
from app.users.repository import UserRepository
from app.users.security import PasswordHasher
from app.users.session import SessionManager


class UserManager:
    def __init__(self, database: str, memory=None, *, auth_enabled=True) -> None:
        self.repository, self.memory, self.auth_enabled = UserRepository(database), memory, auth_enabled
        self.hasher = PasswordHasher()
        self.sessions = SessionManager(self.repository, self._load_user, self._clear_private_context)
        if self.sessions.get_active_user_id() is None:
            owner = next((u for u in self.repository.list(enabled_only=True) if u.role is UserRole.OWNER), None)
            if owner: self.sessions.start_session(owner.id, authenticated=not auth_enabled or self.repository.password_hash(owner.id) is None)
    def _clear_private_context(self):
        if self.memory: self.memory.clear_working()
    def _load_user(self, user_id):
        self._clear_private_context()
        if self.memory: self.memory.set_active_user(user_id)
    def active_user(self):
        user_id=self.sessions.get_active_user_id(); return self.repository.get(user_id) if user_id else None
    def context(self):
        user=self.active_user()
        if not user: return None
        preferences=self.repository.preferences(user.id); permissions={name for name,level in ROLE_PERMISSIONS[user.role].items() if level != "off"}
        return UserContext(user.id,user.display_name,preferences,permissions,user.default_project_id,user.default_iot_device_id,user.role)
    def switch(self, display_name, password=None):
        user=self.repository.get_by_name(display_name)
        if not user or not user.enabled: raise ValueError("Perfil no disponible.")
        if self.auth_enabled and self.repository.password_hash(user.id) and not self.hasher.verify(password or "", self.repository.password_hash(user.id)): raise PermissionError("Autenticación requerida.")
        self.sessions.switch_user(user.id, authenticated=True); return user
    def lock(self): self.sessions.lock_session()
    def allows(self, capability, *, modifying=False):
        user=self.active_user(); return bool(user and role_allows(user.role, capability, modifying=modifying))
    def set_preference(self,key,value):
        user=self.active_user()
        if not user: raise PermissionError("Selecciona un perfil para continuar.")
        self.repository.set_preference(user.id,key,value)
        changes={"language":value} if key=="language" else {"response_style":value} if key=="response_style" else {}
        if key=="default_project": changes={"default_project_id":value}
        if key=="default_device": changes={"default_iot_device_id":value}
        if changes: self.repository.update(user.id,**changes)
    def set_voice(self,tts_voice,rate=1.0,volume=1.0,language=None):
        user=self.active_user()
        if not user: raise PermissionError("Selecciona un perfil para continuar.")
        voice=VoiceProfile(user.id,tts_voice,rate,volume,language or user.language); self.repository.set_voice(voice); self.repository.update(user.id,preferred_voice=tts_voice); return voice
