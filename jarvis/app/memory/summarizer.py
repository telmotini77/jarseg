from __future__ import annotations


def summarize_messages(messages: list[dict[str, str]], limit: int = 800) -> str:
    """Deterministic compact fallback; remote summarization is intentionally optional."""

    parts = [f"{item.get('role', 'unknown')}: {item.get('content', '').strip()}" for item in messages if item.get("content")]
    return " ".join(parts)[:limit]
