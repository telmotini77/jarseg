from __future__ import annotations

from abc import ABC, abstractmethod

from app.browser.models import BrowserTab, PageSnapshot


class BrowserProviderError(RuntimeError):
    """The browser provider cannot safely complete an operation."""


class BrowserProvider(ABC):
    """Interface that keeps the JARVIS core independent from Playwright."""

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @property
    @abstractmethod
    def running(self) -> bool: ...

    @abstractmethod
    def open_url(self, url: str) -> None: ...

    @abstractmethod
    def current_url(self) -> str: ...

    @abstractmethod
    def current_title(self) -> str: ...

    @abstractmethod
    def list_tabs(self) -> list[BrowserTab]: ...

    @abstractmethod
    def new_tab(self, url: str | None = None) -> None: ...

    @abstractmethod
    def close_tab(self) -> None: ...

    @abstractmethod
    def switch_tab(self, index: int) -> None: ...

    @abstractmethod
    def reload(self) -> None: ...

    @abstractmethod
    def back(self) -> None: ...

    @abstractmethod
    def forward(self) -> None: ...

    @abstractmethod
    def read_snapshot(self) -> PageSnapshot: ...

    @abstractmethod
    def find_text(self, query: str) -> int: ...

    @abstractmethod
    def click_element(self, element_id: str) -> None: ...

    @abstractmethod
    def fill_element(self, element_id: str, text: str) -> None: ...

    @abstractmethod
    def select_option(self, element_id: str, text: str) -> None: ...

    @abstractmethod
    def scroll(self, amount: int | None = None, position: str | None = None) -> None: ...

    def media_control(self, action: str) -> bool:
        """Optional capability; legacy providers remain valid without media control."""
        raise BrowserProviderError("Este proveedor no admite control multimedia.")
