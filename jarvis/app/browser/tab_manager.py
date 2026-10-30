from __future__ import annotations

from dataclasses import dataclass

from app.browser.models import BrowserTab
from app.browser.provider import BrowserProvider


@dataclass(slots=True)
class TabManager:
    provider: BrowserProvider

    def list_tabs(self) -> list[BrowserTab]:
        return self.provider.list_tabs()

    def get_active_tab(self) -> BrowserTab | None:
        return next((tab for tab in self.list_tabs() if tab.active), None)

    def new_tab(self, url: str | None = None) -> None:
        self.provider.new_tab(url)

    def close_tab(self) -> None:
        self.provider.close_tab()

    def switch_tab(self, index: int) -> None:
        self.provider.switch_tab(index)
