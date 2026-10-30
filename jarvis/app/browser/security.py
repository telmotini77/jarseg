from __future__ import annotations

import re
from enum import Enum
from urllib.parse import urlsplit, urlunsplit

from app.browser.forms import is_sensitive_field
from app.browser.models import BrowserElement


BROWSER_ACTION_REGISTRY: frozenset[str] = frozenset({
    "browser_start", "browser_stop", "browser_home", "browser_about", "browser_open", "browser_search", "browser_back", "browser_forward",
    "browser_search_history",
    "browser_reload", "browser_new_tab", "browser_close_tab", "browser_switch_tab", "browser_click",
    "browser_scroll", "browser_current_page", "browser_list_tabs", "browser_read_page", "browser_summarize",
    "browser_ask_page", "browser_find_text", "browser_list_links", "browser_open_link", "browser_fill", "browser_fill_email",
    "browser_select", "browser_submit", "browser_sequence",
    "media_play_youtube", "media_pause", "media_resume", "media_volume_up", "media_volume_down", "media_fullscreen",
})
_RESTRICTED_MARKERS = frozenset({
    "buy", "comprar", "pay", "pagar", "payment", "pago", "transfer", "banco", "bank", "delete",
    "eliminar", "remove", "password", "contraseña", "otp", "publish", "publicar", "change password",
})


class BrowserSecurityError(ValueError):
    """A requested browser action is not safe in JARVIS v0.5."""


class BrowserElementRisk(str, Enum):
    SAFE = "safe"
    CONFIRMATION = "confirmation"
    RESTRICTED = "restricted"


def normalize_url(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise BrowserSecurityError("Indica una dirección web.")
    explicit_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", cleaned)
    if explicit_scheme and not cleaned.casefold().startswith(("http://", "https://")):
        raise BrowserSecurityError("Solo se permiten direcciones http o https válidas.")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parsed = urlsplit(cleaned)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise BrowserSecurityError("Solo se permiten direcciones http o https válidas.")
    try:
        _ = parsed.port
    except ValueError as error:
        raise BrowserSecurityError("La dirección web no tiene un puerto válido.") from error
    return urlunsplit((parsed.scheme.casefold(), parsed.netloc, parsed.path or "/", parsed.query, ""))


def validate_url(value: str) -> bool:
    try:
        normalize_url(value)
    except BrowserSecurityError:
        return False
    return True


def is_secure_web_url(value: str) -> bool:
    """True only for a valid HTTPS page; used before entering private data."""
    try:
        return urlsplit(normalize_url(value)).scheme == "https"
    except BrowserSecurityError:
        return False


def assess_element(element: BrowserElement) -> BrowserElementRisk:
    if is_sensitive_field(element):
        return BrowserElementRisk.RESTRICTED
    description = " ".join(item for item in (element.text, element.aria_label, element.href) if item).casefold()
    if any(marker in description for marker in _RESTRICTED_MARKERS):
        return BrowserElementRisk.RESTRICTED
    return BrowserElementRisk.CONFIRMATION
