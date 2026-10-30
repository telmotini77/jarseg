from __future__ import annotations

from urllib.parse import urlsplit

from app.browser.security import normalize_url


KNOWN_BROWSER_SITES: dict[str, str] = {
    "google": "https://www.google.com/",
    "gmail": "https://mail.google.com/",
    "google login": "https://accounts.google.com/",
    "inicio de sesion de google": "https://accounts.google.com/",
    "youtube": "https://www.youtube.com/",
    "github": "https://github.com/",
}


def site_or_url(value: str) -> str:
    return KNOWN_BROWSER_SITES.get(value.strip().casefold(), normalize_url(value))


def display_domain(url: str) -> str:
    return urlsplit(url).netloc.casefold().removeprefix("www.")
