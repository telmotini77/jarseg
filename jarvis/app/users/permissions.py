from __future__ import annotations

from app.users.models import UserRole


ROLE_PERMISSIONS: dict[UserRole, dict[str, str]] = {
    UserRole.OWNER: {"memory": "full", "system": "full", "browser": "full", "terminal": "confirm", "code": "full", "iot": "full", "cyberseg": "full", "productivity": "full", "automation": "full", "users": "full"},
    UserRole.STANDARD: {"memory": "own", "system": "safe", "browser": "safe", "terminal": "read", "code": "assist", "iot": "config", "cyberseg": "read", "productivity": "own", "automation": "own"},
    UserRole.GUEST: {"memory": "temp", "system": "limited", "browser": "read", "terminal": "off", "code": "off", "iot": "read", "cyberseg": "read", "productivity": "off", "automation": "off"},
}


def role_allows(role: UserRole, capability: str, *, modifying: bool = False) -> bool:
    level = ROLE_PERMISSIONS[role].get(capability, "off")
    if level == "off":
        return False
    if modifying and level in {"read", "temp", "limited"}:
        return False
    return True
