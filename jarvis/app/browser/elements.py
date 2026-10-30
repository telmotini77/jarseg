from __future__ import annotations

from app.browser.models import BrowserElement


def element_label(element: BrowserElement) -> str:
    return element.text or element.aria_label or element.placeholder or element.name or "elemento sin etiqueta"


def match_elements(elements: list[BrowserElement], target: str) -> list[BrowserElement]:
    needle = target.casefold().strip()
    exact = [item for item in elements if element_label(item).casefold() == needle]
    if exact:
        return exact
    return [item for item in elements if needle in element_label(item).casefold()]
