from __future__ import annotations

import subprocess
from urllib.parse import quote_plus, urlparse
import webbrowser

from app.commands.apps import resolve_chrome_launch_command
from app.commands.base import CommandResult


KNOWN_SITES: dict[str, tuple[str, str]] = {
    "youtube": ("YouTube", "https://www.youtube.com/"),
    "youtube music": ("YouTube Music", "https://music.youtube.com/"),
    "github": ("GitHub", "https://github.com/"),
    "google": ("Google", "https://www.google.com/"),
    "gmail": ("Gmail", "https://mail.google.com/"),
    "whatsapp web": ("WhatsApp Web", "https://web.whatsapp.com/"),
}


class BrowserService:
    def __init__(self, chrome_profile: str = "last_used") -> None:
        self._chrome_profile = chrome_profile

    def open_url(self, url: str) -> CommandResult:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return CommandResult(False, "La dirección web no es válida.")
        if not self._open_in_chrome(url):
            return CommandResult(False, "No pude abrir el navegador predeterminado.")
        return CommandResult(True, "Abriendo la página web.")

    def open_site(self, site: str) -> CommandResult:
        item = KNOWN_SITES.get(site)
        if item is None:
            return CommandResult(False, "Ese sitio no está registrado en la lista segura.")
        name, url = item
        result = self.open_url(url)
        return CommandResult(result.success, f"Abriendo {name}." if result.success else result.message)

    @staticmethod
    def known_site_url(site: str) -> str | None:
        item = KNOWN_SITES.get(site.casefold().strip())
        return item[1] if item else None

    def search(self, query: str) -> CommandResult:
        cleaned = query.strip()
        if not cleaned:
            return CommandResult(False, "Indica qué quieres buscar.")
        url = f"https://www.google.com/search?q={quote_plus(cleaned)}"
        if not self._open_in_chrome(url):
            return CommandResult(False, "No pude abrir el navegador predeterminado.")
        return CommandResult(True, f"Buscando {cleaned}.")

    def _open_in_chrome(self, url: str) -> bool:
        command = resolve_chrome_launch_command(self._chrome_profile, url)
        if command is not None:
            try:
                subprocess.Popen(list(command), shell=False)
                return True
            except OSError:
                return False
        return webbrowser.open(url, new=2)
