from __future__ import annotations

import re


_WAKE_WORD_PATTERN = re.compile(r"^\s*(?:jarvis|javis|yarvis|jarviz)\b[\s,;:.-]*(.*)$", re.IGNORECASE)


def extract_wake_command(transcript: str) -> str | None:
    """Return a normalized command only when the transcription starts with the wake word.

    Variantes frecuentes de la transcripción española (``Javis``, ``Yarvis`` y
    ``Jarviz``) se aceptan; el resto recibe siempre la forma canónica ``Jarvis``.
    """
    match = _WAKE_WORD_PATTERN.match(transcript)
    if match is None:
        return None

    command = match.group(1).strip()
    return "Jarvis" if not command else f"Jarvis {command}"
