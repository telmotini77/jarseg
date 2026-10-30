from __future__ import annotations

import re
from dataclasses import dataclass


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b", re.IGNORECASE),
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\b(?:password|contraseña|contrasena|api[_ -]?key|token|otp|cvv)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(?:authorization|cookie|set-cookie|database_url|connection_string)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(?:ssh-rsa|ssh-ed25519)\s+[A-Za-z0-9+/=]{24,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
)


@dataclass(frozen=True, slots=True)
class SanitizedContent:
    content: str
    redacted: bool


def sanitize_for_storage(content: str) -> SanitizedContent:
    sanitized = content.strip()
    redacted = False
    for pattern in _SECRET_PATTERNS:
        sanitized, replacements = pattern.subn("[REDACTED_SECRET]", sanitized)
        redacted = redacted or replacements > 0
    return SanitizedContent(sanitized, redacted)


def contains_sensitive_content(content: str) -> bool:
    """Detecta secretos para rechazar su persistencia, incluso si serían redactados."""
    return any(pattern.search(content) for pattern in _SECRET_PATTERNS)
