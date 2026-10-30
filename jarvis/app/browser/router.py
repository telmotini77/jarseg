from __future__ import annotations

import re
from collections.abc import Callable

from app.automation.action import Action
from app.automation.action_queue import ActionQueue
from app.browser.browser_manager import BrowserManager
from app.browser.forms import validate_email_address
from app.browser.security import BROWSER_ACTION_REGISTRY
from app.commands.base import Command, CommandResult
from app.commands.classifier import normalize_text
from app.security.permissions import SecurityLevel


_ORDINALS = {"primera": 0, "primer": 0, "primero": 0, "segunda": 1, "segundo": 1, "tercera": 2, "tercero": 2, "cuarta": 3, "cuarto": 3}
_CHROME_SUFFIX = r"\s+en\s+(?:(?:google\s+)?(?:chrome|crome|crhome|chrom))\s*$"
_SEARCH_ENGINE_SUFFIX = r"\s+en\s+(google|bing|duckduckgo|duck\s+duck\s+go|youtube)\s*$"
_SURVIVOR_ALIASES = frozenset({"survivor", "survival", "survivo", "servivor", "sobrevivor"})
_SURVIVOR_ALIAS_PATTERN = "(?:" + "|".join(sorted(_SURVIVOR_ALIASES)) + ")"
_SURVIVOR_CONTEXT_SUFFIX = re.compile(
    rf"\s+(?:en|en\s+el|dentro\s+de(?:l)?)\s+(?:navegador\s+)?{_SURVIVOR_ALIAS_PATTERN}\s*$",
    re.IGNORECASE,
)
_SPOKEN_DOMAINS = {
    "youtube punto com": "youtube.com",
    "youtube com": "youtube.com",
    "you tube punto com": "youtube.com",
    "you tube com": "youtube.com",
}
_DIRECT_URL_PATTERN = re.compile(r"(?:https?://)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/[^\s]*)?", re.IGNORECASE)


class BrowserRouter:
    """Natural-language parser and allow-listed dispatcher for browser actions."""

    def __init__(self, manager: BrowserManager) -> None:
        self._manager = manager
        self.handlers: dict[str, Callable[[Command], CommandResult]] = {
            "browser_start": lambda _command: self._manager.start(),
            "browser_stop": lambda _command: self._manager.stop(),
            "browser_home": lambda _command: self._manager.home(),
            "browser_about": lambda _command: self._manager.about(),
            "browser_open": lambda command: self._manager.open(command.target or ""),
            "browser_search": lambda command: self._manager.search(
                str(command.arguments.get("query", "")),
                str(command.arguments["engine"]) if isinstance(command.arguments.get("engine"), str) else None,
            ),
            "browser_search_history": lambda _command: self._manager.search_history(),
            "browser_back": lambda _command: self._manager.navigate("back"),
            "browser_forward": lambda _command: self._manager.navigate("forward"),
            "browser_reload": lambda _command: self._manager.navigate("reload"),
            "browser_new_tab": lambda command: self._manager.new_tab(command.target),
            "browser_close_tab": lambda _command: self._manager.close_tab(),
            "browser_switch_tab": self._switch_tab,
            "browser_scroll": self._scroll,
            "browser_current_page": lambda _command: self._manager.current_page(),
            "browser_list_tabs": lambda _command: self._manager.list_tabs(),
            "browser_read_page": lambda _command: self._manager.read_page(),
            "browser_summarize": lambda command: self._manager.summarize(str(command.arguments.get("question", "")) or "Resume los puntos principales de esta página."),
            "browser_ask_page": lambda command: self._manager.summarize(str(command.arguments.get("question", ""))),
            "browser_find_text": lambda command: self._manager.find_text(str(command.arguments.get("query", ""))),
            "browser_list_links": lambda _command: self._manager.list_links(),
            "browser_open_link": lambda command: self._manager.open_link(command.target or ""),
            "browser_click": lambda command: self._manager.click(command.target or ""),
            "browser_fill": lambda command: self._manager.fill(str(command.arguments.get("field", "")), str(command.arguments.get("text", ""))),
            "browser_fill_email": lambda command: self._manager.fill_email(str(command.arguments.get("field", "")), str(command.arguments.get("email", ""))),
            "browser_select": lambda command: self._manager.select(str(command.arguments.get("text", ""))),
            "browser_submit": lambda command: self._manager.click(command.target or ""),
            "browser_sequence": self._sequence,
            "media_play_youtube": lambda command: self._manager.play_youtube(str(command.arguments.get("query", ""))),
            "media_pause": lambda _command: self._manager.media_control("pause"),
            "media_resume": lambda _command: self._manager.media_control("resume"),
            "media_volume_up": lambda _command: self._manager.media_control("volume_up"),
            "media_volume_down": lambda _command: self._manager.media_control("volume_down"),
            "media_fullscreen": lambda _command: self._manager.media_control("fullscreen"),
        }

    def parse(self, raw: str, cleaned: str | None = None) -> Command | None:
        normalized = cleaned or normalize_text(raw)
        # Explicitly leave local searches to CommandRouter/FileService; they must
        # never be sent to a web search engine.
        if re.match(r"^(?:busca|buscar|encuentra)\s+(?:localmente|en mi equipo|en (?:mis )?archivos)\b", normalized) or re.match(
            r"^(?:busca|buscar|encuentra)\s+.+?\s+(?:en|de)\s+(?:escritorio|documentos|descargas|imagenes|fotos|videos|musica)$", normalized
        ):
            return None
        web_search = re.match(r"^(?:busca|consulta|investiga)\s+(?:en internet|en la web|en linea|online)\s+(.+)$", raw, re.IGNORECASE)
        if web_search:
            return Command("browser_search", arguments={"query": web_search.group(1).strip()})
        # Login is intentionally delegated to the user's regular Chrome
        # profile by CommandRouter, rather than the Playwright-controlled one.
        # That prevents identity providers from treating it as an automated
        # browser session.
        if re.match(r"^(?:inicia(?:r)? sesion|accede) (?:en |a )?(google|gmail)$", normalized):
            return None
        youtube = re.match(r"^(?:reproduce|pon|toca)\s+(.+?)(?:\s+en youtube)?$", raw, re.IGNORECASE)
        if youtube and "youtube" in normalized:
            return Command("media_play_youtube", arguments={"query": youtube.group(1).removesuffix(" en YouTube").strip()})
        if normalized in {"pausa", "pausa el video", "pausalo"}: return Command("media_pause")
        if normalized in {"continua", "continua el video", "reanudalo"}: return Command("media_resume")
        if normalized in {"sube el volumen", "sube volumen"}: return Command("media_volume_up")
        if normalized in {"baja el volumen", "baja volumen"}: return Command("media_volume_down")
        if normalized in {"pon pantalla completa", "pantalla completa"}: return Command("media_fullscreen")
        compound = re.match(r"^abre (google|youtube|github) y busca\s+(.+)$", raw, re.IGNORECASE)
        if compound:
            site, query = compound.groups()
            return self._sequence_command((
                {"action": "browser_open", "target": site},
                {"action": "browser_search", "query": query.strip()},
            ))
        compound_search = re.match(r"^busca\s+(.+?)(?:,?\s+(?:y\s+)?abre)\s+(?:la )?documentaci[oó]n oficial(?: y resume (?:la )?p[aá]gina)?$", raw, re.IGNORECASE)
        if compound_search:
            query = compound_search.group(1).strip()
            steps: list[dict[str, str]] = [
                {"action": "browser_search", "query": query},
                {"action": "browser_open_link", "target": "documentación oficial"},
            ]
            if "resume" in normalized:
                steps.append({"action": "browser_summarize"})
            return self._sequence_command(tuple(steps))

        survivor_about = {f"que es {name}" for name in _SURVIVOR_ALIASES} | {f"estado de {name}" for name in _SURVIVOR_ALIASES}
        survivor_open = {
            f"{verb}{article} {name}"
            for verb in ("abre", "abrir")
            for article in ("", " el")
            for name in _SURVIVOR_ALIASES
        }
        if normalized in survivor_about | {"que es el navegador de jarvis"}:
            return Command("browser_about")
        if normalized in survivor_open | {"abre el navegador", "abre navegador"}:
            return Command("browser_start")
        if normalized in {"cierra el navegador", "cierra navegador"}:
            return Command("browser_stop")
        if normalized in {"inicio", "ve al inicio", "abre la pagina de inicio", "abre la página de inicio"}:
            return Command("browser_home")
        if normalized in {"abre una nueva pestana", "abre nueva pestana"}:
            return Command("browser_new_tab")
        new_tab = re.match(r"^abre (?:una )?nueva pesta[nñ]a (?:con|en)\s+(.+)$", raw, re.IGNORECASE)
        if new_tab:
            return Command("browser_new_tab", target=new_tab.group(1).strip())
        if normalized in {"cierra esta pestana", "cierra la pestana"}:
            return Command("browser_close_tab")
        tab = re.match(r"^cambia a la (.+?) pestana$", normalized)
        if tab:
            index = _ORDINALS.get(tab.group(1))
            if index is not None:
                return Command("browser_switch_tab", arguments={"index": index})
        tab_number = re.match(r"^(?:cambia a|abre) (?:la )?pesta[nñ]a (\d+)$", normalized)
        if tab_number:
            return Command("browser_switch_tab", arguments={"index": int(tab_number.group(1)) - 1})
        if normalized in {"vuelve atras", "ve a la pagina anterior", "pagina anterior"}:
            return Command("browser_back")
        if normalized in {"ve hacia adelante", "vuelve hacia adelante", "pagina siguiente"}:
            return Command("browser_forward")
        if normalized in {"recarga", "recarga la pagina"}:
            return Command("browser_reload")
        if normalized in {"dime que pestanas tengo abiertas", "dime mis pestanas"}:
            return Command("browser_list_tabs")
        if normalized in {"historial de busquedas", "historial de búsqueda", "muestra mi historial de busquedas", "muestra mi historial de búsqueda"}:
            return Command("browser_search_history")
        if normalized in {"dime que pagina tengo abierta", "que pagina tengo abierta"}:
            return Command("browser_current_page")
        if normalized in {"lee esta pagina", "lee la pagina"}:
            return Command("browser_read_page")
        if normalized in {"resume esta pagina", "dime los puntos principales"}:
            return Command("browser_summarize")
        page_question = re.match(r"^(?:que dice esta pagina sobre|cuales son los requisitos|que tecnologias menciona|hay algun ejemplo de codigo)\s*(.*)$", normalized)
        if page_question:
            question = raw if page_question.group(1) != "que dice esta pagina sobre" else f"¿Qué dice esta página sobre {page_question.group(2)}?"
            return Command("browser_ask_page", arguments={"question": question})
        find = re.match(r"^busca (?:la palabra )?[\"']?(.+?)[\"']? en esta pagina$", raw, re.IGNORECASE)
        if find:
            return Command("browser_find_text", arguments={"query": find.group(1).strip(' \"\'')})
        if normalized in {"dime que enlaces aparecen", "dime los enlaces"}:
            return Command("browser_list_links")
        if normalized in {"baja", "baja la pagina", "baja un poco"}:
            return Command("browser_scroll", arguments={"amount": 600})
        if normalized in {"sube", "sube la pagina", "sube un poco"}:
            return Command("browser_scroll", arguments={"amount": -600})
        if normalized in {"ve al final", "ve hasta el final"}:
            return Command("browser_scroll", arguments={"position": "bottom"})
        if normalized in {"vuelve arriba", "ve arriba"}:
            return Command("browser_scroll", arguments={"position": "top"})
        fill = re.match(r"^escribe\s+[\"']?(.+?)[\"']?\s+en (?:el |la )?(.+)$", raw, re.IGNORECASE)
        if fill:
            text, field = fill.groups()
            value = text.strip(' \"\'')
            try:
                email = validate_email_address(value)
            except ValueError:
                return Command("browser_fill", arguments={"text": value, "field": field.strip()})
            return Command("browser_fill_email", arguments={"email": email, "field": field.strip()})
        selection = re.match(r"^selecciona\s+(.+)$", raw, re.IGNORECASE)
        if selection:
            return Command("browser_select", arguments={"text": selection.group(1).strip()})
        click = re.match(r"^(?:haz click en|haz clic en|pulsa|selecciona)\s+(.+)$", raw, re.IGNORECASE)
        if click and not re.search(r"\d+\s*,\s*\d+", raw):
            return Command("browser_click", target=click.group(1).strip())
        open_link = re.match(r"^abre (?:el enlace de|el resultado de)\s+(.+)$", raw, re.IGNORECASE)
        if open_link:
            return Command("browser_open_link", target=open_link.group(1).strip())
        if normalized in {"abre el primero", "abre el primer resultado", "abre el primer sitio", "abre el primer enlace"}:
            return Command("browser_open_link", target="__first_result__")
        if normalized.startswith("abre documentacion") or normalized.startswith("abre documentación"):
            return Command("browser_open_link", target="documentación")
        result = re.match(r"^abre (?:el )?(?:resultado )?(\d+|primero|primer|segundo|tercero)$", normalized)
        if result:
            ordinal = result.group(1)
            index = _ORDINALS.get(ordinal, int(ordinal) - 1 if ordinal.isdigit() else -1)
            return Command("browser_open_link", target=f"__result_{index + 1}__") if index >= 0 else None
        submit = re.match(r"^(?:envia|enviar|confirma|publica|publicar)\s*(.*)$", raw, re.IGNORECASE)
        if submit:
            return Command("browser_submit", target=submit.group(1).strip() or "enviar")
        search = re.match(r"^(?:busca|consulta|investiga)\s+(.+)$", raw, re.IGNORECASE)
        if search:
            query = re.sub(_CHROME_SUFFIX, "", search.group(1), flags=re.IGNORECASE).strip()
            query = _SURVIVOR_CONTEXT_SUFFIX.sub("", query).strip()
            engine_match = re.search(_SEARCH_ENGINE_SUFFIX, query, flags=re.IGNORECASE)
            engine = None
            if engine_match:
                engine = engine_match.group(1).casefold().replace(" ", "")
                query = query[:engine_match.start()].strip()
            spoken_domain = _SPOKEN_DOMAINS.get(normalize_text(query))
            if spoken_domain is not None:
                query = spoken_domain
            if _DIRECT_URL_PATTERN.fullmatch(query):
                return Command("browser_open", target=query)
            arguments = {"query": query}
            if engine:
                arguments["engine"] = engine
            return Command("browser_search", arguments=arguments) if query else None
        open_page = re.match(r"^abre\s+(.+)$", raw, re.IGNORECASE)
        if open_page:
            target = open_page.group(1).strip()
            if target.casefold() in {"google", "youtube", "github"} or "." in target or target.startswith(("http://", "https://")):
                return Command("browser_open", target=target)
        navigate = re.match(r"^(?:navega a|ve a)\s+(.+)$", raw, re.IGNORECASE)
        if navigate:
            target = navigate.group(1).strip()
            if "." in target or target.startswith(("http://", "https://")):
                return Command("browser_open", target=target)
        return None

    def execute(self, command: Command) -> CommandResult:
        if command.action not in BROWSER_ACTION_REGISTRY:
            return CommandResult(False, "Esa acción de navegador no está registrada.")
        handler = self.handlers.get(command.action)
        return handler(command) if handler else CommandResult(False, "Esa acción de navegador no está implementada.")

    @staticmethod
    def _sequence_command(steps: tuple[dict[str, str], ...]) -> Command:
        return Command("browser_sequence", arguments={"steps": steps})

    def _switch_tab(self, command: Command) -> CommandResult:
        index = command.arguments.get("index")
        return self._manager.switch_tab(index) if isinstance(index, int) else CommandResult(False, "Indica una pestaña válida.")

    def _scroll(self, command: Command) -> CommandResult:
        amount = command.arguments.get("amount")
        position = command.arguments.get("position")
        return self._manager.scroll(amount if isinstance(amount, int) else None, position if isinstance(position, str) else None)

    def _sequence(self, command: Command) -> CommandResult:
        raw_steps = command.arguments.get("steps")
        if not isinstance(raw_steps, tuple):
            return CommandResult(False, "La secuencia de navegador no es válida.")
        queue = ActionQueue()
        for step in raw_steps:
            action = step.get("action") if isinstance(step, dict) else None
            if not isinstance(action, str) or action not in BROWSER_ACTION_REGISTRY or action == "browser_sequence":
                return CommandResult(False, "La secuencia contiene una acción de navegador no registrada.")
            parameters = {key: value for key, value in step.items() if key not in {"action", "target"}}
            queue.enqueue(Action(action, step.get("target"), parameters, SecurityLevel.SAFE))
        messages: list[str] = []
        while (action := queue.pop_next()) is not None:
            result = self.execute(Command(action.action_type, action.target, dict(action.parameters)))
            if not result.success:
                queue.cancel()
                return result
            messages.append(result.message)
        return CommandResult(True, " ".join(messages))
