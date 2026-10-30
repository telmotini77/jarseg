from __future__ import annotations

import re

from app.browser.models import BrowserElement


_EMAIL_PATTERN = re.compile(r"(?=.{1,254}\Z)[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\Z", re.IGNORECASE)


SENSITIVE_FIELD_MARKERS = frozenset({
    "password", "contraseña", "contrasena", "credit", "card", "tarjeta", "cvv", "bank", "banco",
    "payment", "pago", "otp", "token", "secret", "api key", "clave",
})
EMAIL_FIELD_MARKERS = frozenset({"email", "e-mail", "correo", "mail"})


def is_sensitive_field(element: BrowserElement) -> bool:
    if (element.input_type or "").casefold() == "password":
        return True
    description = " ".join(
        item for item in (element.text, element.aria_label, element.name, element.placeholder) if item
    ).casefold()
    return any(marker in description for marker in SENSITIVE_FIELD_MARKERS)


def is_email_field(element: BrowserElement) -> bool:
    """Return whether the page explicitly identifies an input as an email field."""
    if (element.input_type or "").casefold() == "email":
        return True
    description = " ".join(
        item for item in (element.aria_label, element.name, element.placeholder) if item
    ).casefold()
    return any(marker in description for marker in EMAIL_FIELD_MARKERS)


def validate_email_address(value: str) -> str:
    """Validate a single conventional email address without retaining its value."""
    candidate = value.strip()
    if candidate != value or any(character.isspace() or ord(character) < 32 for character in candidate):
        raise ValueError("El correo no puede contener espacios ni caracteres de control.")
    if not _EMAIL_PATTERN.fullmatch(candidate):
        raise ValueError("Indica una dirección de correo electrónico válida.")
    return candidate


def field_label(element: BrowserElement) -> str:
    return element.aria_label or element.placeholder or element.name or "ese campo"
