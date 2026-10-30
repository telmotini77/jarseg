from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.browser.models import BrowserElement, BrowserTab, PageSnapshot
from app.browser.page_reader import clean_visible_text, concise_items
from app.browser.provider import BrowserProvider, BrowserProviderError


_DOM_SELECTOR = "a, button, input, select, textarea, [role='button'], [role='checkbox'], form"


@dataclass(slots=True)
class PlaywrightProvider(BrowserProvider):
    """A visible browser profile controlled by JARVIS, separate from personal Chrome."""

    profile_dir: Path
    headless: bool = False
    timeout_ms: int = 20_000
    channel: str = "chromium"
    chromium_sandbox: bool = True
    _playwright: Any = field(default=None, init=False, repr=False)
    _context: Any = field(default=None, init=False, repr=False)
    _active_index: int = field(default=0, init=False)
    _element_indexes: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    @property
    def running(self) -> bool:
        return self._context is not None

    def start(self) -> None:
        if self.running:
            return
        try:
            from playwright.sync_api import sync_playwright

            self.profile_dir.mkdir(parents=True, exist_ok=True)
            self._playwright = sync_playwright().start()
            self._context = self._playwright.chromium.launch_persistent_context(
                str(self.profile_dir),
                headless=self.headless,
                viewport={"width": 1280, "height": 900},
                channel=None if self.channel == "chromium" else self.channel,
                chromium_sandbox=self.chromium_sandbox,
            )
            self._context.set_default_timeout(self.timeout_ms)
            if not self._context.pages:
                self._context.new_page()
            self._active_index = len(self._context.pages) - 1
        except Exception as error:
            self._cleanup()
            browser = "Google Chrome" if self.channel == "chrome" else "Chromium"
            raise BrowserProviderError(f"No pude iniciar {browser}. Ejecuta: py -m playwright install chromium") from error

    def stop(self) -> None:
        self._cleanup()

    def _cleanup(self) -> None:
        try:
            if self._context is not None:
                self._context.close()
        finally:
            self._context = None
            try:
                if self._playwright is not None:
                    self._playwright.stop()
            finally:
                self._playwright = None
                self._element_indexes.clear()

    def _page(self) -> Any:
        if not self.running:
            raise BrowserProviderError("El navegador de JARVIS no está iniciado.")
        pages = self._context.pages
        if not pages:
            self._context.new_page()
            pages = self._context.pages
        self._active_index = min(max(self._active_index, 0), len(pages) - 1)
        return pages[self._active_index]

    def open_url(self, url: str) -> None:
        try:
            self._page().goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude cargar esa página a tiempo.") from error

    def current_url(self) -> str:
        return str(self._page().url)

    def current_title(self) -> str:
        try:
            return str(self._page().title())
        except Exception as error:
            raise BrowserProviderError("No pude leer el título de la página.") from error

    def list_tabs(self) -> list[BrowserTab]:
        if not self.running:
            return []
        tabs: list[BrowserTab] = []
        for index, page in enumerate(self._context.pages):
            try:
                title = str(page.title()) or "Página sin título"
            except Exception:
                title = "Página sin título"
            tabs.append(BrowserTab(index, title, str(page.url), index == self._active_index))
        return tabs

    def new_tab(self, url: str | None = None) -> None:
        if not self.running:
            self.start()
        page = self._context.new_page()
        self._active_index = len(self._context.pages) - 1
        page.bring_to_front()
        if url:
            self.open_url(url)

    def close_tab(self) -> None:
        page = self._page()
        if len(self._context.pages) == 1:
            page.goto("about:blank", wait_until="domcontentloaded")
            return
        page.close()
        self._active_index = min(self._active_index, len(self._context.pages) - 1)
        self._page().bring_to_front()

    def switch_tab(self, index: int) -> None:
        if not self.running or not 0 <= index < len(self._context.pages):
            raise BrowserProviderError("Esa pestaña no existe.")
        self._active_index = index
        self._page().bring_to_front()

    def reload(self) -> None:
        try:
            self._page().reload(wait_until="domcontentloaded", timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude recargar la página a tiempo.") from error

    def back(self) -> None:
        try:
            self._page().go_back(wait_until="domcontentloaded", timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude volver a la página anterior.") from error

    def forward(self) -> None:
        try:
            self._page().go_forward(wait_until="domcontentloaded", timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude avanzar a la siguiente página.") from error

    def read_snapshot(self) -> PageSnapshot:
        page = self._page()
        try:
            title = self.current_title() or "Página sin título"
            text = clean_visible_text(page.locator("body").inner_text(timeout=self.timeout_ms))
            headings = concise_items(page.locator("h1, h2, h3").all_inner_texts())
            raw_elements = page.locator(_DOM_SELECTOR).evaluate_all(
                """nodes => nodes.map((element, index) => {
                    const style = window.getComputedStyle(element);
                    const rect = element.getBoundingClientRect();
                    const visible = style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                    const tag = element.tagName.toLowerCase();
                    const role = element.getAttribute('role') || '';
                    let kind = tag;
                    if (tag === 'a') kind = 'link';
                    else if (tag === 'button' || role === 'button') kind = 'button';
                    else if (tag === 'input') kind = 'input';
                    else if (tag === 'select') kind = 'select';
                    else if (tag === 'textarea') kind = 'textarea';
                    return {index, visible, kind, text: (element.innerText || element.textContent || '').trim(),
                        ariaLabel: element.getAttribute('aria-label'), href: tag === 'a' ? element.href : null,
                        inputType: element.getAttribute('type'), name: element.getAttribute('name'),
                        placeholder: element.getAttribute('placeholder'), isDownload: tag === 'a' && element.hasAttribute('download')};
                }).filter(item => item.visible)"""
            )
        except Exception as error:
            raise BrowserProviderError("No pude leer el contenido visible de la página.") from error

        self._element_indexes.clear()
        elements: list[BrowserElement] = []
        for item in raw_elements[:100]:
            identifier = f"dom-{item['index']}"
            self._element_indexes[identifier] = int(item["index"])
            elements.append(BrowserElement(
                id=identifier, element_type=str(item["kind"]), text=str(item["text"]) or None,
                aria_label=item["ariaLabel"], href=item["href"], input_type=item["inputType"],
                name=item["name"], placeholder=item["placeholder"], is_download=bool(item["isDownload"]),
            ))
        return PageSnapshot(
            title, self.current_url(), headings, text,
            [item for item in elements if item.element_type == "link"],
            [item for item in elements if item.element_type == "button"],
            [item for item in elements if item.element_type in {"input", "select", "textarea"}],
            [item for item in elements if item.element_type == "form"],
        )

    def find_text(self, query: str) -> int:
        if not query.strip():
            raise BrowserProviderError("Indica el texto que quieres encontrar.")
        try:
            locator = self._page().get_by_text(query, exact=False)
            count = int(locator.count())
            if count:
                locator.first.scroll_into_view_if_needed(timeout=self.timeout_ms)
            return count
        except Exception as error:
            raise BrowserProviderError("No pude buscar ese texto en la página.") from error

    def _locator_for(self, element_id: str) -> Any:
        index = self._element_indexes.get(element_id)
        if index is None:
            self.read_snapshot()
            index = self._element_indexes.get(element_id)
        if index is None:
            raise BrowserProviderError("Ese elemento ya no está disponible en la página.")
        return self._page().locator(_DOM_SELECTOR).nth(index)

    def click_element(self, element_id: str) -> None:
        try:
            self._locator_for(element_id).click(timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude activar ese elemento de la página.") from error

    def fill_element(self, element_id: str, text: str) -> None:
        try:
            self._locator_for(element_id).fill(text, timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude rellenar ese campo de la página.") from error

    def select_option(self, element_id: str, text: str) -> None:
        try:
            self._locator_for(element_id).select_option(label=text, timeout=self.timeout_ms)
        except Exception as error:
            raise BrowserProviderError("No pude seleccionar esa opción de la página.") from error

    def scroll(self, amount: int | None = None, position: str | None = None) -> None:
        try:
            if position == "top":
                self._page().evaluate("window.scrollTo(0, 0)")
            elif position == "bottom":
                self._page().evaluate("window.scrollTo(0, document.body.scrollHeight)")
            else:
                self._page().evaluate("amount => window.scrollBy(0, amount)", amount or 600)
        except Exception as error:
            raise BrowserProviderError("No pude desplazar la página.") from error

    def media_control(self, action: str) -> bool:
        """Use DOM/media APIs only; never screen coordinates."""
        scripts = {
            "pause": "() => { const v=document.querySelector('video'); if(!v) return false; v.pause(); return true; }",
            "resume": "() => { const v=document.querySelector('video'); if(!v) return false; v.play().then(()=>{}).catch(()=>{}); return true; }",
            "volume_up": "() => { const v=document.querySelector('video,audio'); if(!v) return false; v.volume=Math.min(1,v.volume+.1); return true; }",
            "volume_down": "() => { const v=document.querySelector('video,audio'); if(!v) return false; v.volume=Math.max(0,v.volume-.1); return true; }",
            "fullscreen": "() => { const v=document.querySelector('video'); if(!v) return false; v.requestFullscreen?.().catch(()=>{}); return true; }",
        }
        if action not in scripts:
            raise BrowserProviderError("Control multimedia no válido.")
        try:
            return bool(self._page().evaluate(scripts[action]))
        except Exception as error:
            raise BrowserProviderError("No pude controlar el contenido multimedia visible.") from error
