from __future__ import annotations

import logging
from urllib.parse import quote_plus
from collections.abc import Callable
from dataclasses import dataclass, field

from app.browser.content_security import build_web_analysis_request
from app.browser.elements import element_label, match_elements
from app.browser.forms import field_label, is_email_field, is_sensitive_field, validate_email_address
from app.browser.models import BrowserContextState, BrowserElement, SearchResult
from app.browser.navigation import display_domain, site_or_url
from app.browser.navigator import NAVIGATOR_DESCRIPTION, NAVIGATOR_NAME, NAVIGATOR_VERSION, navigator_home
from app.browser.provider import BrowserProvider, BrowserProviderError
from app.browser.search import SearchReport, build_search_report, build_search_url
from app.browser.security import BrowserElementRisk, BrowserSecurityError, assess_element, is_secure_web_url, normalize_url
from app.browser.tab_manager import TabManager
from app.commands.base import CommandResult


@dataclass(slots=True)
class BrowserManager:
    provider: BrowserProvider
    search_engine: str = "google"
    answerer: Callable[[list[dict[str, str]]], str] | None = None
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("jarvis.browser"))
    memory: object | None = None
    _tabs: TabManager = field(init=False, repr=False)
    _last_search_engine: str | None = field(default=None, init=False, repr=False)
    _last_search_query: str | None = field(default=None, init=False, repr=False)
    _search_history: list[SearchReport] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        self._tabs = TabManager(self.provider)

    def set_answerer(self, answerer: Callable[[list[dict[str, str]]], str]) -> None:
        self.answerer = answerer

    def state(self) -> BrowserContextState:
        if not self.provider.running:
            return BrowserContextState(False, None)
        tabs = self._tabs.list_tabs()
        active = self._tabs.get_active_tab()
        return BrowserContextState(True, active.index if active else None, tabs, active.url if active else None, active.title if active else None)

    def start(self) -> CommandResult:
        try:
            self.provider.start()
            return CommandResult(True, f"{NAVIGATOR_NAME} listo.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def stop(self) -> CommandResult:
        self.provider.stop()
        return CommandResult(True, f"{NAVIGATOR_NAME} cerrado.")

    def _ensure_started(self) -> None:
        if not self.provider.running:
            self.provider.start()

    def open(self, target: str) -> CommandResult:
        try:
            self._ensure_started()
            url = site_or_url(target)
            self.provider.open_url(url)
            final_url = self.provider.current_url()
            title = self.provider.current_title() or display_domain(final_url)
            self.logger.info("BROWSER action=open url=%s", final_url)
            if self.memory is not None:
                try:
                    self.memory.remember_browser_reference(final_url, title)
                except Exception as error:
                    self.logger.warning("MEMORY browser bridge skipped reason=%s", type(error).__name__)
            return CommandResult(True, f"{title} está abierto correctamente. {final_url}")
        except (BrowserProviderError, BrowserSecurityError) as error:
            return CommandResult(False, str(error))

    def home(self) -> CommandResult:
        """Open the selected search provider's safe home page in Survivor."""
        return self.open(navigator_home(self.search_engine))

    def navigator_status(self) -> dict[str, object]:
        state = self.state()
        return {
            "name": NAVIGATOR_NAME,
            "version": NAVIGATOR_VERSION,
            "description": NAVIGATOR_DESCRIPTION,
            "rendering_engine": "Google Chrome" if self.provider.__class__.__name__ == "PlaywrightProvider" else "navegador compatible",
            "search_provider": self.search_engine,
            "running": state.running,
            "tab_count": len(state.tabs),
            "current_url": state.current_url,
        }

    def about(self) -> CommandResult:
        status = self.navigator_status()
        return CommandResult(
            True,
            f"{status['name']}: {status['description']} "
            f"Motor de renderizado: {status['rendering_engine']}. "
            f"Buscador predeterminado: {status['search_provider']}.",
        )

    def search(self, query: str, engine: str | None = None) -> CommandResult:
        try:
            self._ensure_started()
            selected = (engine or self.search_engine).casefold().strip()
            self.provider.open_url(build_search_url(query, selected))
            if self.memory is not None:
                try:
                    self.memory.update_working(last_url=self.provider.current_url(), current_topic=query)
                except Exception:
                    pass
            snapshot = self._snapshot()
            report = build_search_report(query, selected, snapshot)
            self._last_search_engine, self._last_search_query = selected, query.strip()
            self._search_history = [report, *self._search_history][:20]
            if report.requires_manual_verification:
                return CommandResult(
                    False,
                    "Google solicitó una verificación anti-robots en la ventana de Chrome de JARVIS. "
                    "Complétala manualmente; JARVIS no la elude ni resuelve CAPTCHAs.",
                )
            results = list(report.results)
            self.logger.info("BROWSER action=search engine=%s query_length=%s", selected, len(query))
            if not results:
                return CommandResult(True, f"Busqué {query} con {selected}. Aún no encontré resultados visibles.")
            lines = [f"{item.index}. {item.title} — {item.domain}" for item in results]
            return CommandResult(True, f"Encontré resultados para {query} con {selected}:\n" + "\n".join(lines))
        except (BrowserProviderError, BrowserSecurityError, ValueError) as error:
            return CommandResult(False, str(error))

    def search_results(self) -> list[SearchResult]:
        snapshot = self._snapshot()
        report = build_search_report(self._last_search_query or "resultado", self._last_search_engine or self.search_engine, snapshot)
        return list(report.results)

    def search_history(self) -> CommandResult:
        if not self._search_history:
            return CommandResult(True, "No hay búsquedas en esta sesión de JARVIS.")
        lines = [
            f"{index}. [{item.engine}] {item.query} — {len(item.results)} resultado(s)"
            for index, item in enumerate(self._search_history, 1)
        ]
        return CommandResult(True, "Historial de búsqueda de esta sesión:\n" + "\n".join(lines))

    def new_tab(self, url: str | None = None) -> CommandResult:
        try:
            self._ensure_started()
            self._tabs.new_tab(site_or_url(url) if url else None)
            return CommandResult(True, "Nueva pestaña abierta.")
        except (BrowserProviderError, BrowserSecurityError) as error:
            return CommandResult(False, str(error))

    def close_tab(self) -> CommandResult:
        try:
            self._ensure_started()
            self._tabs.close_tab()
            return CommandResult(True, "Pestaña cerrada.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def switch_tab(self, index: int) -> CommandResult:
        try:
            self._ensure_started()
            self._tabs.switch_tab(index)
            tab = self._tabs.get_active_tab()
            self.logger.info("BROWSER action=tab_switch index=%s", index + 1)
            return CommandResult(True, f"Pestaña activa: {tab.title if tab else index + 1}.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def list_tabs(self) -> CommandResult:
        try:
            self._ensure_started()
            tabs = self._tabs.list_tabs()
            if not tabs:
                return CommandResult(True, "No hay pestañas abiertas.")
            lines = [f"{tab.index + 1}. {tab.title}{' (activa)' if tab.active else ''}" for tab in tabs[:12]]
            return CommandResult(True, "Pestañas abiertas:\n" + "\n".join(lines))
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def current_page(self) -> CommandResult:
        try:
            self._ensure_started()
            return CommandResult(True, f"Estás en {self.provider.current_title() or 'una página'}: {self.provider.current_url()}")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def navigate(self, operation: str) -> CommandResult:
        try:
            self._ensure_started()
            operations = {"back": self.provider.back, "forward": self.provider.forward, "reload": self.provider.reload}
            operations[operation]()
            labels = {"back": "Volví a la página anterior.", "forward": "Avancé a la siguiente página.", "reload": "Página recargada."}
            return CommandResult(True, labels[operation])
        except (BrowserProviderError, KeyError) as error:
            return CommandResult(False, str(error))

    def play_youtube(self, query: str) -> CommandResult:
        """Search YouTube and open its first visible result through the DOM."""
        try:
            self._ensure_started()
            self.provider.open_url("https://www.youtube.com/results?search_query=" + quote_plus(query))
            snapshot = self._snapshot()
            candidates = [link for link in snapshot.links if link.href and "/watch" in link.href]
            if not candidates:
                return CommandResult(False, "No encontré un resultado reproducible en YouTube.")
            self.provider.open_url(candidates[0].href)
            try: self.provider.media_control("resume")
            except BrowserProviderError: pass
            return CommandResult(True, f"Reproduciendo {query} en YouTube.")
        except (BrowserProviderError, BrowserSecurityError) as error:
            return CommandResult(False, str(error))

    def media_control(self, action: str) -> CommandResult:
        try:
            self._ensure_started()
            if not self.provider.media_control(action):
                return CommandResult(False, "No encontré contenido multimedia activo.")
            labels = {"pause": "Video pausado.", "resume": "Video reanudado.", "volume_up": "Volumen del video aumentado.", "volume_down": "Volumen del video reducido.", "fullscreen": "Pantalla completa activada."}
            return CommandResult(True, labels[action])
        except (BrowserProviderError, KeyError) as error:
            return CommandResult(False, str(error))

    def scroll(self, amount: int | None = None, position: str | None = None) -> CommandResult:
        try:
            self._ensure_started()
            self.provider.scroll(amount, position)
            return CommandResult(True, "Volví arriba." if position == "top" else "Fui al final." if position == "bottom" else "Desplacé la página.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def read_page(self) -> CommandResult:
        try:
            snapshot = self._snapshot()
            preview = snapshot.text[:1_000] or "No encontré texto visible."
            headings = "; ".join(snapshot.headings[:5]) or "sin encabezados detectados"
            return CommandResult(True, f"{snapshot.title}\n{snapshot.url}\nEncabezados: {headings}\n{preview}")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def summarize(self, question: str = "Resume los puntos principales de esta página.") -> CommandResult:
        if self.answerer is None:
            return CommandResult(False, "No hay un proveedor de IA configurado para resumir la página.")
        try:
            snapshot = self._snapshot()
            response = self.answerer([{"role": "user", "content": build_web_analysis_request(question, snapshot)}])
            return CommandResult(True, response)
        except Exception:
            return CommandResult(False, "No pude analizar el contenido visible de esta página.")

    def find_text(self, query: str) -> CommandResult:
        try:
            self._ensure_started()
            count = self.provider.find_text(query)
            return CommandResult(True, f"Encontré {count} coincidencias para {query}." if count else f"No encontré {query} en esta página.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def list_links(self) -> CommandResult:
        try:
            links = self._snapshot().links[:15]
            if not links:
                return CommandResult(True, "No encontré enlaces visibles.")
            return CommandResult(True, "Enlaces visibles:\n" + "\n".join(f"- {element_label(link)}" for link in links))
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def open_link(self, target: str) -> CommandResult:
        try:
            if target == "__first_result__":
                results = self.search_results()
                if not results:
                    return CommandResult(False, "No encontré resultados para abrir.")
                return self.open(results[0].url)
            if target.startswith("__result_") and target.endswith("__"):
                try:
                    result_index = int(target.removeprefix("__result_").removesuffix("__"))
                except ValueError:
                    return CommandResult(False, "Indica un resultado válido.")
                results = self.search_results()
                if not 1 <= result_index <= len(results):
                    return CommandResult(False, "Ese resultado no está disponible.")
                return self.open(results[result_index - 1].url)
            snapshot = self._snapshot()
            matches = match_elements(snapshot.links, target)
            if not matches:
                matches = [
                    link for link in snapshot.links
                    if link.href and target.casefold().strip() in display_domain(link.href)
                ]
            if not matches:
                return CommandResult(False, "No encontré un enlace con ese texto.")
            if len(matches) > 1:
                names = "; ".join(element_label(item) for item in matches[:3])
                return CommandResult(False, f"El enlace es ambiguo: {names}.")
            link = matches[0]
            if link.is_download:
                return CommandResult(False, f"Detecté una descarga desde {display_domain(link.href or '')}. No inicio descargas automáticamente.")
            if not link.href:
                return CommandResult(False, "Ese enlace no tiene una dirección segura.")
            return self.open(link.href)
        except (BrowserProviderError, BrowserSecurityError) as error:
            return CommandResult(False, str(error))

    def click(self, target: str) -> CommandResult:
        try:
            snapshot = self._snapshot()
            matches = match_elements([*snapshot.buttons, *snapshot.links], target)
            if not matches:
                return CommandResult(False, "No encontré un botón o enlace con ese texto.")
            if len(matches) > 1:
                return CommandResult(False, "Hay varios elementos con ese texto; especifica mejor el objetivo.")
            element = matches[0]
            risk = assess_element(element)
            if risk is BrowserElementRisk.RESTRICTED:
                return CommandResult(False, "Ese elemento parece relacionado con una acción sensible o restringida; no lo activaré.")
            if element.is_download:
                return CommandResult(False, "Detecté una descarga. JARVIS no descarga ni ejecuta archivos automáticamente.")
            self.provider.click_element(element.id)
            self.logger.info("BROWSER action=click target=%s", element_label(element))
            return CommandResult(True, f"Activé {element_label(element)}.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def fill(self, field: str, text: str) -> CommandResult:
        try:
            snapshot = self._snapshot()
            matches = match_elements(snapshot.inputs, field)
            if not matches and field.casefold() in {"buscador", "busqueda", "búsqueda", "search"}:
                matches = snapshot.inputs
            if len(matches) != 1:
                return CommandResult(False, "No encontré un único campo seguro con ese nombre.")
            element = matches[0]
            if is_sensitive_field(element):
                return CommandResult(False, "Ese campo contiene información sensible y debe completarse manualmente.")
            self.provider.fill_element(element.id, text)
            self.logger.info("BROWSER action=fill field=%s text_length=%s", field_label(element), len(text))
            return CommandResult(True, f"Escribí texto en {field_label(element)}.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def fill_email(self, field: str, email: str) -> CommandResult:
        """Enter an email only in a declared email input over HTTPS.

        Email values are deliberately never included in logs, messages, history, or memory.
        """
        try:
            address = validate_email_address(email)
            snapshot = self._snapshot()
            if not is_secure_web_url(snapshot.url):
                return CommandResult(False, "Por seguridad, el correo solo se completa en páginas HTTPS.")
            matches = match_elements(snapshot.inputs, field)
            if len(matches) != 1:
                return CommandResult(False, "No encontré un único campo de correo con ese nombre.")
            element = matches[0]
            if is_sensitive_field(element) or not is_email_field(element):
                return CommandResult(False, "Solo puedo completar un campo identificado explícitamente como correo electrónico.")
            self.provider.fill_element(element.id, address)
            self.logger.info("BROWSER action=fill_email field=%s", field_label(element))
            return CommandResult(True, "Correo electrónico completado en un campo HTTPS verificado. Revísalo antes de enviar el formulario.")
        except (BrowserProviderError, ValueError) as error:
            return CommandResult(False, str(error))

    def select(self, text: str) -> CommandResult:
        try:
            selects = [element for element in self._snapshot().inputs if element.element_type == "select"]
            if len(selects) != 1:
                return CommandResult(False, "No encontré un único selector seguro en esta página.")
            element = selects[0]
            if is_sensitive_field(element):
                return CommandResult(False, "Ese campo contiene información sensible y debe completarse manualmente.")
            self.provider.select_option(element.id, text)
            self.logger.info("BROWSER action=select field=%s text_length=%s", field_label(element), len(text))
            return CommandResult(True, f"Seleccioné {text} en {field_label(element)}.")
        except BrowserProviderError as error:
            return CommandResult(False, str(error))

    def _snapshot(self) -> PageSnapshot:
        self._ensure_started()
        return self.provider.read_snapshot()
