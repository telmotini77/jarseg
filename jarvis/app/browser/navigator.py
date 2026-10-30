"""Product identity and safe home pages for the JARVIS browser experience."""

from __future__ import annotations


NAVIGATOR_NAME = "Survivor"
NAVIGATOR_VERSION = "1.0"
NAVIGATOR_DESCRIPTION = "Navegador asistido con pestañas, lectura DOM y acciones protegidas."

_HOME_PAGES: dict[str, str] = {
    "google": "https://www.google.com/",
    "bing": "https://www.bing.com/",
    "duckduckgo": "https://duckduckgo.com/",
    "youtube": "https://www.youtube.com/",
}


def navigator_home(engine: str) -> str:
    """Return a deliberate, allow-listed home page for a supported provider."""
    return _HOME_PAGES.get(engine.casefold().strip(), _HOME_PAGES["google"])
