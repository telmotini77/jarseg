from __future__ import annotations

import re
from pathlib import Path

from app.code.models import CodeRiskLevel
from app.memory.sensitive_filter import contains_sensitive_content, sanitize_for_storage


_PROTECTED_NAMES = {".env", "id_rsa", "credentials", "secrets"}
_PROTECTED_SUFFIXES = {".pem", ".key", ".pfx", ".p12"}
_SENSITIVE_PATH_PARTS = {".github", ".gitlab", "docker", "infra", "terraform", "migrations"}


def validate_project_path(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def protected_file(path: Path) -> bool:
    name = path.name.casefold()
    return name in _PROTECTED_NAMES or name.startswith(".env.") or name.startswith("credentials.") or name.startswith("secrets.") or path.suffix.casefold() in _PROTECTED_SUFFIXES


def safe_text(content: str) -> str:
    return sanitize_for_storage(content).content


def may_read(path: Path) -> bool:
    return not protected_file(path)


def patch_risk(paths: list[Path], *, deletes: bool = False) -> CodeRiskLevel:
    if deletes or any(protected_file(path) for path in paths):
        return CodeRiskLevel.RESTRICTED
    parts = {part.casefold() for path in paths for part in path.parts}
    if parts & _SENSITIVE_PATH_PARTS or any(re.search(r"(?:auth|security|permission|payment)", path.name, re.IGNORECASE) for path in paths):
        return CodeRiskLevel.SENSITIVE
    return CodeRiskLevel.CONFIRMATION


def secret_free(content: str) -> bool:
    return not contains_sensitive_content(content)
