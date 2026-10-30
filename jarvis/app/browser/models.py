from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class BrowserElement:
    id: str
    element_type: str
    text: str | None = None
    aria_label: str | None = None
    href: str | None = None
    input_type: str | None = None
    name: str | None = None
    placeholder: str | None = None
    is_download: bool = False


@dataclass(frozen=True, slots=True)
class BrowserTab:
    index: int
    title: str
    url: str
    active: bool = False


@dataclass(frozen=True, slots=True)
class BrowserContextState:
    running: bool
    active_tab: int | None
    tabs: list[BrowserTab] = field(default_factory=list)
    current_url: str | None = None
    current_title: str | None = None


@dataclass(frozen=True, slots=True)
class PageSnapshot:
    title: str
    url: str
    headings: list[str]
    text: str
    links: list[BrowserElement]
    buttons: list[BrowserElement]
    inputs: list[BrowserElement]
    forms: list[BrowserElement]


@dataclass(frozen=True, slots=True)
class SearchResult:
    index: int
    title: str
    url: str
    domain: str
