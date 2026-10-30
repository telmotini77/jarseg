from __future__ import annotations

import re


MAX_PAGE_TEXT = 12_000


def clean_visible_text(text: str, limit: int = MAX_PAGE_TEXT) -> str:
    """Return bounded visible text only; raw HTML is never supplied to the model."""

    return re.sub(r"\s+", " ", text).strip()[:limit]


def concise_items(items: list[str], limit: int = 12) -> list[str]:
    return [clean_visible_text(item, 300) for item in items if clean_visible_text(item, 300)][:limit]
