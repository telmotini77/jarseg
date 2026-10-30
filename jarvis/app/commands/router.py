from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from app.automation.action import Action
from app.automation.action_queue import ActionQueue
from app.automation.registry import is_registered_action
from app.automation.routines.manager import RoutineManager
from app.browser.browser_manager import BrowserManager
from app.code.agent import CodeAgent
from app.cyberseg.client import CyberSegClient, CyberSegClientError
from app.cyberseg.threat_intelligence import coverage_report, enrich_alerts
from app.iot.agent import IoTAgent
from app.browser.router import BrowserRouter
from app.terminal.manager import TerminalManager
from app.terminal.router import TerminalRouter
from app.commands.apps import ApplicationService
from app.commands.base import ALLOWED_COMMANDS, Command, CommandName, CommandResult, Route, RouteType
from app.commands.browser import BrowserService, KNOWN_SITES
from app.commands.classifier import IntentClassifier, normalize_text
from app.commands.files import FOLDER_ALIASES, FileService
from app.input.keyboard import ALLOWED_HOTKEYS, ALLOWED_KEYS, KeyboardController, is_sensitive_window
from app.input.mouse import MouseController
from app.memory.manager import MemoryManager
from app.security.permissions import SecurityLevel
from app.system.audio_control import AudioController
from app.system.system_info import SystemInfoService
from app.system.window_manager import WindowManager
from app.tasks.manager import ReminderManager
from app.vision.service import VisionService
from app.automation_engine.models import Automation, AutomationAction, EventTrigger, ManualTrigger, TimeTrigger


class CommandRouter:
    """Despachador determinista y limitado de comandos para JARVIS v0.7."""

    _exit_pattern = re.compile(r"^(?:jarvis[ ,]*)?(salir|cerrar)$", re.IGNORECASE)
    _cancel_pattern = re.compile(r"^(?:jarvis[ ,]*)?(detener|detente|cancela|cancelar|para)$", re.IGNORECASE)

    def __init__(
        self,
        classifier: IntentClassifier | None = None,
        applications: ApplicationService | None = None,
        browser: BrowserService | None = None,
        files: FileService | None = None,
        system_info: SystemInfoService | None = None,
        audio: AudioController | None = None,
        windows: WindowManager | None = None,
        mouse: MouseController | None = None,
        keyboard: KeyboardController | None = None,
        vision: VisionService | None = None,
        memory: MemoryManager | None = None,
        reminders: ReminderManager | None = None,
        routines: RoutineManager | None = None,
        browser_agent: BrowserManager | None = None,
        terminal_agent: TerminalManager | None = None,
        code_agent: CodeAgent | None = None,
        iot_agent: IoTAgent | None = None,
        cyberseg_client: CyberSegClient | None = None,
        orchestrator: object | None = None,
        agent_registry: object | None = None,
        automation_engine: object | None = None,
        user_manager: object | None = None,
    ) -> None:
        self._classifier = classifier or IntentClassifier()
        self._applications = applications or ApplicationService()
        self._browser = browser or BrowserService()
        self._files = files or FileService()
        self._system_info = system_info or SystemInfoService()
        self._audio = audio or AudioController()
        self._windows = windows or WindowManager()
        self._mouse = mouse or MouseController()
        self._keyboard = keyboard or KeyboardController()
        self._vision = vision or VisionService.create_default(self._windows, self._mouse)
        self._memory = memory
        self._users = user_manager
        self._reminders = reminders
        self._routines = routines
        self._browser_router = BrowserRouter(browser_agent) if browser_agent is not None else None
        self._terminal_router = TerminalRouter(terminal_agent) if terminal_agent is not None else None
        self._code_agent = code_agent
        self._iot_agent = iot_agent
        self._cyberseg = cyberseg_client
        self._orchestrator = orchestrator
        self._agent_registry = agent_registry
        self._automation_engine = automation_engine
        self._active_queue: ActionQueue | None = None
        self._handlers: dict[str, Callable[[Command], CommandResult]] = {
            "open_application": lambda command: self._applications.open(command.target),
            "list_applications": lambda command: self._applications.list_available(command.target),
            "close_application": lambda command: self._applications.close(command.target),
            "system_info": lambda command: self._system_info.info(str(command.arguments.get("metric", "status"))),
            "set_volume": self._handle_set_volume,
            "volume_up": lambda _command: self._audio.volume_up(),
            "volume_down": lambda _command: self._audio.volume_down(),
            "open_url": self._handle_open_url,
            "web_search": lambda command: self._browser.search(str(command.arguments.get("query", ""))),
            "browser_trusted_login": self._handle_trusted_browser_login,
            "open_folder": lambda command: self._files.open_folder(command.target),
            "list_files": lambda command: self._files.list_files(command.target),
            "search_local_files": lambda command: self._files.search_files(command.target, str(command.arguments.get("query", ""))),
            "capture_screen": lambda _command: self._vision_result(self._vision.capture_screen),
            "capture_active_window": lambda _command: self._vision_result(self._vision.capture_active_window),
            "analyze_screen": lambda command: self._vision_result(
                lambda: self._vision.analyze_screen(str(command.arguments.get("question", "")))
            ),
            "analyze_active_window": lambda command: self._vision_result(
                lambda: self._vision.analyze_screen(str(command.arguments.get("question", "")), active_window=True)
            ),
            "list_windows": lambda _command: self._windows.list_open_windows(),
            "active_window": lambda _command: self._windows.active_window(),
            "focus_window": lambda command: self._windows.focus_window(command.target),
            "focus_previous_window": lambda _command: self._windows.focus_previous_window(),
            "minimize_window": lambda command: self._windows.minimize_window(command.target),
            "maximize_window": lambda command: self._windows.maximize_window(command.target),
            "restore_window": lambda command: self._windows.restore_window(command.target),
            "wait_for_window": self._handle_wait_for_window,
            "move_mouse": self._handle_move_mouse,
            "move_mouse_center": lambda _command: self._mouse.move_to_center(),
            "mouse_position": self._handle_mouse_position,
            "mouse_click": self._handle_mouse_click,
            "mouse_double_click": self._handle_mouse_double_click,
            "mouse_right_click": self._handle_mouse_right_click,
            "scroll": self._handle_scroll,
            "type_text": self._handle_type_text,
            "press_key": lambda command: self._keyboard.press_key(str(command.arguments.get("key", ""))),
            "hotkey": lambda command: self._keyboard.hotkey(str(command.arguments.get("name", ""))),
            "automation_sequence": self._handle_automation_sequence,
            "memory_remember": self._handle_memory_remember,
            "memory_recall": self._handle_memory_recall,
            "memory_forget": self._handle_memory_forget,
            "memory_update": self._handle_memory_update,
            "memory_explain": self._handle_memory_explain,
            "memory_when": self._handle_memory_when,
            "memory_stats": self._handle_memory_stats,
            "memory_export": self._handle_memory_export,
            "memory_clear_all": self._handle_memory_clear_all,
            "memory_last_session": self._handle_memory_last_session,
            "memory_backup": self._handle_memory_backup,
            "code_scan_project": self._handle_code_scan,
            "code_read_file": self._handle_code_explain,
            "code_search": self._handle_code_search,
            "code_explain": self._handle_code_explain,
            "code_plan_change": self._handle_code_plan,
            "code_project_plan": self._handle_project_plan,
            "code_project_apply": self._handle_project_apply,
            "code_apply_patch": self._handle_code_apply,
            "code_create_file": self._handle_code_plan,
            "code_rename_file": self._handle_code_plan,
            "code_delete_file": self._handle_code_plan,
            "code_run_tests": lambda _command: self._code_result(lambda: self._code().run_tests()),
            "code_run_lint": lambda _command: self._code_result(lambda: self._code().run_lint()),
            "code_run_build": lambda _command: self._code_result(lambda: self._code().run_build()),
            "code_review": lambda _command: self._code_result(lambda: self._code().review()),
            "code_open_vscode": self._handle_code_vscode,
            "code_architecture": lambda _command: self._code_result(lambda: self._code().architecture()),
            "code_dependencies": lambda _command: self._code_result(lambda: self._code().dependencies()),
            "code_changed_files": lambda _command: self._code_result(lambda: self._code().changed_summary()),
            "code_diff": lambda _command: self._code_result(lambda: self._code().show_diff()),
            "code_diagnostics": self._handle_code_diagnostics,
            "code_commit": self._handle_code_commit,
            "iot_connect": lambda _command: self._iot_result(lambda: self._iot().connect()),
            "iot_disconnect": lambda _command: self._iot_result(lambda: self._iot().disconnect()),
            "iot_list_devices": self._handle_iot_list_devices,
            "iot_get_state": self._handle_iot_get_state,
            "iot_get_telemetry": self._handle_iot_get_telemetry,
            "iot_set_led": self._handle_iot_command,
            "iot_set_relay": self._handle_iot_command,
            "iot_set_servo": self._handle_iot_command,
            "iot_set_buzzer": self._handle_iot_command,
            "iot_subscribe": self._handle_iot_subscribe,
            "iot_create_rule": self._handle_iot_create_rule,
            "iot_register_device": self._handle_iot_register,
            "iot_list_rules": self._handle_iot_list_rules,
            "iot_disable_rule": self._handle_iot_disable_rules,
            "iot_disable_all_rules": lambda _command: self._iot_result(lambda: self._iot().disable_rules()),
            "iot_check_tools": self._handle_iot_check_tools,
            "cyberseg_status": lambda _command: self._cyberseg_result(lambda: self._cyberseg_client().status()),
            "cyberseg_alerts": self._handle_cyberseg_alerts,
            "cyberseg_threat_coverage": lambda _command: CommandResult(True, coverage_report()),
            "cyberseg_start_capture": lambda _command: self._cyberseg_result(lambda: self._cyberseg_client().start_capture()),
            "cyberseg_stop_capture": lambda _command: self._cyberseg_result(lambda: self._cyberseg_client().stop_capture()),
            "orchestrator_agents": self._handle_orchestrator_agents,
            "orchestrator_agent_status": self._handle_orchestrator_agent_status,
            "orchestrator_set_mode": self._handle_orchestrator_set_mode,
            "orchestrator_goal": self._handle_orchestrator_goal,
            "orchestrator_status": self._handle_orchestrator_status,
            "orchestrator_cancel": self._handle_orchestrator_cancel,
            "automation_list_engine": self._handle_automation_list_engine,
            "automation_create_engine": self._handle_automation_create_engine,
            "automation_enable_engine": self._handle_automation_enable_engine,
            "automation_disable_engine": self._handle_automation_disable_engine,
            "automation_run_engine": self._handle_automation_run_engine,
            "reminder_create": self._handle_reminder_create,
            "reminder_list": self._handle_reminder_list,
            "reminder_list_today": self._handle_reminder_list_today,
            "reminder_cancel": self._handle_reminder_cancel,
            "reminder_complete": self._handle_reminder_complete,
            "routine_begin": self._handle_routine_begin,
            "routine_add": self._handle_routine_add,
            "routine_save": self._handle_routine_save,
            "routine_execute": self._handle_routine_execute,
            "user_active": self._handle_user_active,
            "user_list": self._handle_user_list,
            "user_switch": self._handle_user_switch,
            "user_lock": self._handle_user_lock,
            "user_preference": self._handle_user_preference,
            "user_voice": self._handle_user_voice,
            "user_permissions": self._handle_user_permissions,
        }
        if self._browser_router is not None:
            self._handlers.update(self._browser_router.handlers)
        if self._terminal_router is not None:
            self._handlers.update(self._terminal_router.handlers)

    def route(self, text: str) -> Route:
        normalized = normalize_text(text)
        user_command = self._parse_user_command(text, normalized)
        if user_command is not None:
            return Route(type=RouteType.COMMAND, parsed_command=user_command)
        if self._cancel_pattern.match(normalized):
            return Route(type=RouteType.COMMAND, command=CommandName.CANCEL)
        if self._exit_pattern.match(normalized):
            return Route(type=RouteType.COMMAND, command=CommandName.EXIT)

        trusted_login = self._parse_trusted_browser_login(normalized)
        if trusted_login is not None:
            return Route(type=RouteType.COMMAND, parsed_command=trusted_login)
        cyberseg_command = self._parse_cyberseg_command(text, normalized)
        if cyberseg_command is not None:
            return Route(type=RouteType.COMMAND, parsed_command=cyberseg_command)
        orchestrator_command = self._parse_orchestrator_command(text, normalized)
        if orchestrator_command is not None:
            return Route(type=RouteType.COMMAND, parsed_command=orchestrator_command)
        # Browser controls are explicit, safe commands. Resolve them before the
        # conversational classifier so "abre Survivor" never falls through to
        # the Windows installed-application catalog.
        if self._browser_router is not None:
            raw = re.sub(r"^jarvis[ ,]*", "", text, flags=re.IGNORECASE).strip(" ¿?¡!.,")
            browser_command = self._browser_router.parse(raw, normalize_text(raw))
            if browser_command is not None:
                return Route(type=RouteType.COMMAND, parsed_command=browser_command)
        intent = self._classifier.classify(text)
        if intent is RouteType.CONVERSATION:
            return Route(type=RouteType.CONVERSATION)
        return Route(type=intent, parsed_command=self.parse(text))

    def parse(self, text: str) -> Command | None:
        raw = re.sub(r"^jarvis[ ,]*", "", text, flags=re.IGNORECASE).strip(" ¿?¡!.,")
        cleaned = normalize_text(raw)

        trusted_login = self._parse_trusted_browser_login(cleaned)
        if trusted_login is not None:
            return trusted_login

        user_command = self._parse_user_command(raw, cleaned)
        if user_command is not None:
            return user_command

        cyberseg_command = self._parse_cyberseg_command(raw, cleaned)
        if cyberseg_command is not None:
            return cyberseg_command

        orchestrator_command = self._parse_orchestrator_command(raw, cleaned)
        if orchestrator_command is not None:
            return orchestrator_command

        if self._iot_agent is not None:
            iot_command = self._parse_iot_command(raw, cleaned)
            if iot_command is not None:
                return iot_command

        if self._code_agent is not None:
            code_command = self._parse_code_command(raw, cleaned)
            if code_command is not None:
                return code_command

        if self._terminal_router is not None:
            terminal_command = self._terminal_router.parse(raw, cleaned)
            if terminal_command is not None:
                return terminal_command

        chrome_tab = self._parse_chrome_tab(raw)
        if chrome_tab is not None:
            return chrome_tab

        persistent = self._parse_persistent_command(raw, cleaned)
        if persistent is not None:
            return persistent

        if self._browser_router is not None:
            browser_command = self._browser_router.parse(raw, cleaned)
            if browser_command is not None:
                return browser_command

        compound = re.match(r"^(?:abre|abrir) (?:el |la )?(.+?) y escribe(?:[: ]+)(.+)$", raw, re.IGNORECASE)
        if compound:
            target, content = compound.groups()
            return self._automation_command(target.strip(), self._clean_written_text(content))

        if self._is_screen_request(cleaned):
            if "captura esta ventana" in cleaned or "captura la ventana" in cleaned:
                return Command("capture_active_window")
            if "ventana" in cleaned and ("mira" in cleaned or "analiza" in cleaned):
                return Command("analyze_active_window", arguments={"question": raw})
            if "captura" in cleaned:
                return Command("capture_screen")
            return Command("analyze_screen", arguments={"question": raw})

        if "ventanas" in cleaned and any(word in cleaned for word in ("dime", "muestrame", "lista", "abiertas")):
            return Command("list_windows")
        if "ventana" in cleaned and "abierta" in cleaned:
            return Command("active_window")
        if cleaned in {"vuelve a la ventana anterior", "vuelve a ventana anterior"}:
            return Command("focus_previous_window")
        focus = re.match(r"^(?:cambia a|cambiar a|vuelve a) (.+)$", cleaned)
        if focus:
            return Command("focus_window", target=focus.group(1).strip())
        for verb, action in (("minimiza", "minimize_window"), ("maximiza", "maximize_window"), ("restaura", "restore_window")):
            match = re.match(rf"^{verb} (.+)$", cleaned)
            if match:
                return Command(action, target=match.group(1).strip())

        if "donde esta" in cleaned and "mouse" in cleaned:
            return Command("mouse_position")
        if re.search(r"mueve (?:el )?(?:mouse|raton) al centro", cleaned):
            return Command("move_mouse_center")
        coordinates = re.search(r"(?:mueve (?:el )?(?:mouse|raton)|(?:haz )?(?:click|clic)) (?:a |en )?(\d+)\s*[, ]\s*(\d+)", cleaned)
        if coordinates:
            x, y = (int(value) for value in coordinates.groups())
            action = "move_mouse" if cleaned.startswith("mueve") else "mouse_click"
            return Command(action, arguments={"x": x, "y": y})
        if "doble click" in cleaned or "doble clic" in cleaned:
            return Command("mouse_double_click")
        if "click derecho" in cleaned or "clic derecho" in cleaned:
            return Command("mouse_right_click")
        if "click aqui" in cleaned or "clic aqui" in cleaned:
            return Command("mouse_click")
        if any(phrase in cleaned for phrase in ("baja la pagina", "desplazate hacia abajo", "baja un poco")):
            return Command("scroll", arguments={"amount": -5})
        if any(phrase in cleaned for phrase in ("sube la pagina", "desplazate hacia arriba", "sube un poco")):
            return Command("scroll", arguments={"amount": 5})

        write = re.match(r"^(?:escribe|escribir)[: ]+(.+)$", raw, re.IGNORECASE)
        if write:
            content = self._clean_written_text(write.group(1))
            return Command(
                "type_text",
                arguments={
                    "text": content,
                    "sensitive": self._active_window_is_sensitive(),
                    "window_title": self._active_window_title(),
                },
            )
        press = re.match(r"^(?:presiona|presionar) (.+)$", cleaned)
        if press:
            key = press.group(1).strip()
            return Command("press_key", arguments={"key": key}) if key in ALLOWED_KEYS else None
        for name, phrases in {
            "copy": ("copia", "copiar"), "paste": ("pega", "pegar"), "select_all": ("selecciona todo",),
            "save": ("guarda", "guardar"), "undo": ("deshaz",), "redo": ("rehaz",), "find": ("buscar en", "encuentra"),
        }.items():
            if any(cleaned == phrase for phrase in phrases):
                return Command("hotkey", arguments={"name": name})

        volume = re.search(r"(?:pon|poner|ajusta) (?:el )?volumen (?:al |a )?(\d+)(?: %| por ciento)?", cleaned)
        if volume:
            return Command("set_volume", arguments={"level": int(volume.group(1))})
        if re.search(r"\bsube\b.*\b(volumen|sonido)\b", cleaned):
            return Command("volume_up")
        if re.search(r"\bbaja\b.*\b(volumen|sonido)\b", cleaned):
            return Command("volume_down")
        if "silencia" in cleaned or "silenciar" in cleaned:
            return Command("set_volume", arguments={"mute": True})
        if "activa el sonido" in cleaned or "activar sonido" in cleaned:
            return Command("set_volume", arguments={"mute": False})
        if "estado del sistema" in cleaned or "estado del computador" in cleaned:
            return Command("system_info", arguments={"metric": "status"})
        applications = re.match(r"^(?:muestra|muestrame|lista|listar|que) (?:las )?(?:aplicaciones|programas)(?: disponibles| instaladas)?(?: (.+))?$", cleaned)
        if applications:
            return Command("list_applications", target=applications.group(1).strip() if applications.group(1) else None)
        if re.search(r"\b(cpu|procesador)\b", cleaned):
            return Command("system_info", arguments={"metric": "cpu"})
        if re.search(r"\b(ram|memoria)\b", cleaned):
            return Command("system_info", arguments={"metric": "memory"})
        if re.search(r"\b(disco|espacio)\b", cleaned):
            return Command("system_info", arguments={"metric": "disk"})
        list_match = re.search(r"^(?:lista|listar)(?: los)? archivos (?:de|en) (.+)$", cleaned)
        if list_match:
            return Command("list_files", target=list_match.group(1).strip())
        local_search = re.match(r"^(?:busca|buscar|encuentra)\s+(?:localmente|en mi equipo|en (?:mis )?archivos)\s+(.+?)\s+(?:en|de)\s+(escritorio|documentos|descargas|imagenes|fotos|videos|musica)$", cleaned)
        if local_search:
            query, folder = local_search.groups()
            return Command("search_local_files", target=folder, arguments={"query": query.strip()})
        local_search = re.match(r"^(?:busca|buscar|encuentra)\s+(.+?)\s+(?:localmente )?(?:en|de)\s+(escritorio|documentos|descargas|imagenes|fotos|videos|musica)$", cleaned)
        if local_search and "internet" not in cleaned and "web" not in cleaned:
            query, folder = local_search.groups()
            return Command("search_local_files", target=folder, arguments={"query": query.strip()})
        web_search = re.match(r"^(?:busca|buscar|consulta|investiga)\s+(?:en internet|en la web|en linea|online)\s+(.+)$", cleaned)
        if web_search:
            return Command("web_search", arguments={"query": web_search.group(1).strip()})
        search_match = re.search(r"^(?:busca|buscar) (.+)$", cleaned)
        if search_match:
            return Command("web_search", arguments={"query": search_match.group(1).strip()})
        close_match = re.search(r"^(?:cierra|cerrar) (.+)$", cleaned)
        if close_match:
            return Command("close_application", target=close_match.group(1).strip())
        open_match = re.search(r"^(?:abre|abrir) (.+)$", cleaned)
        if open_match:
            target = re.sub(r"^(?:la |el )", "", open_match.group(1).strip())
            if target in FOLDER_ALIASES:
                return Command("open_folder", target=target)
            if target in KNOWN_SITES:
                return Command("open_url", target=target)
            if target.startswith(("http://", "https://")):
                return Command("open_url", arguments={"url": target})
            if "." in target and " " not in target:
                return Command("open_url", arguments={"url": f"https://{target}"})
            return Command("open_application", target=target)
        return None

    def _parse_user_command(self, raw: str, cleaned: str) -> Command | None:
        if self._users is None:
            return None
        raw = re.sub(r"^jarvis[ ,]*", "", raw, flags=re.IGNORECASE).strip()
        if any(item in cleaned for item in ("que usuario esta activo", "quien esta activo", "mi perfil")):
            return Command("user_active")
        if any(item in cleaned for item in ("muestrame los perfiles", "muestra los perfiles", "perfiles disponibles")):
            return Command("user_list")
        match = re.search(r"(?:cambia|cambiar) (?:al |a )?(?:perfil )?(.+)$", raw, re.I)
        if match and "idioma" not in cleaned and "dispositivo" not in cleaned:
            return Command("user_switch", arguments={"name": match.group(1).strip()})
        if "bloquea mi sesion" in cleaned or "bloquear sesion" in cleaned:
            return Command("user_lock")
        match = re.search(r"(?:cambia|cambiar) mi idioma a (.+)$", raw, re.I)
        if match: return Command("user_preference", arguments={"key":"language", "value":match.group(1).strip()})
        match = re.search(r"(?:establece|configura) (.+?) como mi proyecto principal", raw, re.I)
        if match: return Command("user_preference", arguments={"key":"default_project", "value":match.group(1).strip()})
        match = re.search(r"(?:cambia|configura) mi dispositivo principal (?:a |al )?(.+)$", raw, re.I)
        if match: return Command("user_preference", arguments={"key":"default_device", "value":match.group(1).strip()})
        if "voz diferente" in cleaned or "usa esta voz" in cleaned:
            return Command("user_voice", arguments={"voice": ""})
        if "dime mis permisos" in cleaned: return Command("user_permissions")
        return None

    def _handle_user_active(self, _command: Command) -> CommandResult:
        user = self._users.active_user() if self._users else None
        return CommandResult(True, f"El perfil activo es {user.display_name}." if user else "Selecciona un perfil para continuar.")

    def _handle_user_list(self, _command: Command) -> CommandResult:
        users = self._users.repository.list(enabled_only=True) if self._users else []
        return CommandResult(True, "Perfiles disponibles: " + ", ".join(user.display_name for user in users))

    def _handle_user_switch(self, command: Command) -> CommandResult:
        try:
            user = self._users.switch(command.arguments.get("name", ""))
            return CommandResult(True, f"Perfil {user.display_name} cargado. Contexto privado actualizado.")
        except (ValueError, PermissionError) as error: return CommandResult(False, str(error))

    def _handle_user_lock(self, _command: Command) -> CommandResult:
        self._users.lock(); return CommandResult(True, "JARVIS LOCKED. Autenticación requerida para continuar.")

    def _handle_user_preference(self, command: Command) -> CommandResult:
        try:
            self._users.set_preference(command.arguments["key"], command.arguments["value"])
            return CommandResult(True, "Preferencia del perfil actualizada.")
        except (KeyError, PermissionError) as error: return CommandResult(False, str(error))

    def _handle_user_voice(self, command: Command) -> CommandResult:
        try:
            self._users.set_voice(command.arguments.get("voice", "")); return CommandResult(True, "Voz del perfil actualizada.")
        except PermissionError as error: return CommandResult(False, str(error))

    def _handle_user_permissions(self, _command: Command) -> CommandResult:
        context = self._users.context() if self._users else None
        return CommandResult(True, "Permisos: " + ", ".join(sorted(context.permissions)) if context else "No hay un perfil activo.")

    @staticmethod
    def _parse_chrome_tab(raw: str) -> Command | None:
        """Abre un sitio explícito en el Chrome personal, no en el perfil aislado de Playwright."""
        chrome_name = r"(?:google\s+)?(?:chrome|crome|crhome|chrom)"
        patterns = (
            rf"^abre\s+(?:una\s+)?(?:nueva\s+)?pesta[nñ]a\s+(?:de|con)\s+(.+?)\s+(?:en|con)\s+{chrome_name}$",
            rf"^abre\s+(.+?)\s+(?:en|con)\s+(?:una\s+)?pesta[nñ]a\s+(?:de\s+)?{chrome_name}$",
            rf"^abre\s+(.+?)\s+(?:en|con)\s+{chrome_name}$",
        )
        target: str | None = None
        for pattern in patterns:
            match = re.match(pattern, raw, re.IGNORECASE)
            if match:
                target = match.group(1).strip().casefold()
                break
        if not target:
            return None
        target = re.sub(r"^(?:la |el )?(?:pagina|página|sitio|web) (?:de )?", "", target).strip()
        known = KNOWN_SITES.get(target)
        if known:
            return Command("open_url", arguments={"url": known[1]})
        if re.fullmatch(r"(?:https?://)?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:/[^\s]*)?", target, re.IGNORECASE):
            return Command("open_url", arguments={"url": target if target.startswith(("http://", "https://")) else f"https://{target}"})
        return None

    def _parse_orchestrator_command(self, raw: str, cleaned: str) -> Command | None:
        if self._orchestrator is None:
            return None
        if any(phrase in cleaned for phrase in ("que agentes tienes", "que agentes estan disponibles", "que agentes están disponibles")):
            return Command("orchestrator_agents")
        if any(phrase in cleaned for phrase in ("estado de tus agentes", "estado de los agentes", "estado agentes")):
            return Command("orchestrator_agent_status")
        modes = {
            "activa modo solo lectura": "read_only", "activa modo asistido": "assist",
            "activa modo autonomo seguro": "autonomous_safe", "activa modo autónomo seguro": "autonomous_safe",
        }
        if cleaned in modes:
            return Command("orchestrator_set_mode", target=modes[cleaned])
        if cleaned in {"estado del orquestador", "estado de la tarea multiagente", "estado de la tarea"}:
            return Command("orchestrator_status")
        if re.match(r"^(?:cancela|deten|detiene) (?:la )?(?:tarea|tarea actual|plan|orquestador)", cleaned):
            return Command("orchestrator_cancel")
        if self._automation_engine is not None:
            if cleaned in {"dime automatizaciones", "lista automatizaciones", "mis automatizaciones"}:
                return Command("automation_list_engine")
            toggle = re.match(r"^(activa|desactiva) (?:la )?(?:automatizacion|automatización|modo) (.+)$", raw, re.IGNORECASE)
            if toggle:
                return Command("automation_enable_engine" if normalize_text(toggle.group(1)) == "activa" else "automation_disable_engine", target=toggle.group(2).strip())
            run = re.match(r"^ejecuta (?:la )?(?:automatizacion|automatización|modo) (.+)$", raw, re.IGNORECASE)
            if run:
                return Command("automation_run_engine", target=run.group(1).strip())
            if cleaned in {"crea modo programacion", "crea modo programación"}:
                return Command("automation_create_engine", arguments={"kind": "programming", "name": "modo programación"})
            time_match = re.match(r"^crea (?:una )?automatizaci[oó]n (.+?) cada ma[nñ]ana a las (\d{1,2})(?::(\d{2}))?$", raw, re.IGNORECASE)
            if time_match:
                name, hour, minute = time_match.groups()
                return Command("automation_create_engine", arguments={"kind": "daily_notice", "name": name.strip(), "time": f"{int(hour):02d}:{minute or '00'}"})
            offline = re.match(r"^(?:cuando|si) (?:el )?esp32 (.+?) se desconecte av[ií]same$", raw, re.IGNORECASE)
            if offline:
                return Command("automation_create_engine", arguments={"kind": "device_offline", "name": f"aviso {offline.group(1).strip()} desconectado", "device": offline.group(1).strip()})
        multiagent_markers = (
            "documentacion oficial", "documentación oficial", "quedo pendiente", "quedó pendiente", "corrige",
            "corregir", "estado del esp32", "ejecuta tests", "ejecuta pruebas", "abre vs code", "abre visual studio code",
        )
        if any(marker in cleaned for marker in multiagent_markers):
            return Command("orchestrator_goal", arguments={"goal": raw.strip()})
        return None

    @staticmethod
    def _parse_persistent_command(raw: str, cleaned: str) -> Command | None:
        remember = re.match(r"^(?:recuerda que|guard[aá] esto(?: que)?|acuerdate de|acuérdate de)\s+(.+)$", raw, re.IGNORECASE)
        if remember:
            return Command("memory_remember", arguments={"content": remember.group(1).strip()})
        forget = re.match(r"^(?:olvida que|olvida|elimina ese recuerdo|borra mi preferencia sobre)\s+(.+)$", raw, re.IGNORECASE)
        if forget:
            return Command("memory_forget", arguments={"query": forget.group(1).strip()})
        update = re.match(r"^(?:cambia|actualiza) (?:la |el )?(?:base de datos|dato|recuerdo)(?: de)?\s+(.+?)\s+(?:a|por)\s+(.+)$", raw, re.IGNORECASE)
        if update:
            subject, value = update.groups()
            return Command("memory_update", arguments={"query": subject.strip(), "content": f"{subject.strip()} usa {value.strip()}."})
        explain = re.match(r"^(?:por qu[eé] recuerdas|por que guardaste)\s+(.+)$", raw, re.IGNORECASE)
        if explain:
            return Command("memory_explain", arguments={"query": explain.group(1).strip()})
        when = re.match(r"^(?:cu[aá]ndo guardaste|cuando guardaste)\s+(.+)$", raw, re.IGNORECASE)
        if when:
            return Command("memory_when", arguments={"query": when.group(1).strip()})
        if cleaned in {"cuanta memoria tienes", "cuantos recuerdos tienes", "estadisticas de memoria", "estadísticas de memoria"}:
            return Command("memory_stats")
        if cleaned in {"borra toda tu memoria", "elimina toda tu memoria", "olvida todo"}:
            return Command("memory_clear_all", arguments={"double_confirmation": False})
        if cleaned in {"que paso en la ultima sesion", "que paso en la última sesion", "que paso en la ultima sesión", "que paso en la última sesión"}:
            return Command("memory_last_session")
        export = re.match(r"^(?:exporta|exportar) (?:tu|tus|mi|mis)?\s*(?:memoria|recuerdos)(?: sobre)?\s*(.*)$", raw, re.IGNORECASE)
        if export:
            return Command("memory_export", arguments={"query": export.group(1).strip() or None})
        if cleaned in {"crea una copia de seguridad de tu memoria", "crea una copia de seguridad de mi memoria"}:
            return Command("memory_backup")
        recall = re.match(r"^(?:qu[eé] recuerdas sobre|qu[eé] me dijiste ayer sobre|d[oó]nde guardo|cu[aá]l es mi)\s+(.+)$", raw, re.IGNORECASE)
        if recall:
            return Command("memory_recall", arguments={"query": recall.group(1).strip()})

        reminder = re.match(r"^recu[eé]rdame\s+(.+)$", raw, re.IGNORECASE)
        if reminder:
            return Command("reminder_create", arguments={"request": reminder.group(1).strip()})
        if cleaned in {"dime mis recordatorios", "que recordatorios tengo"}:
            return Command("reminder_list")
        if cleaned in {"que tengo pendiente hoy", "dime que tengo pendiente hoy"}:
            return Command("reminder_list_today")
        cancel = re.match(r"^cancela (?:mi |el )?recordatorio(?: de)?\s+(.+)$", raw, re.IGNORECASE)
        if cancel:
            return Command("reminder_cancel", arguments={"query": cancel.group(1).strip()})
        complete = re.match(r"^(?:marca|completa) (?:esa |el )?(?:tarea|recordatorio)(?: de)?\s+(.+)$", raw, re.IGNORECASE)
        if complete:
            return Command("reminder_complete", arguments={"query": complete.group(1).strip()})

        create_routine = re.match(r"^crea una rutina llamada\s+(.+)$", raw, re.IGNORECASE)
        if create_routine:
            return Command("routine_begin", target=create_routine.group(1).strip())
        add_routine = re.match(r"^(?:agrega|anade|añade)\s+(.+)$", raw, re.IGNORECASE)
        if add_routine:
            return Command("routine_add", arguments={"instruction": add_routine.group(1).strip()})
        if cleaned in {"guarda la rutina", "guarda rutina", "termina la rutina"}:
            return Command("routine_save")
        run_routine = re.match(r"^(?:activa|ejecuta) (?:la )?(.+)$", raw, re.IGNORECASE)
        if run_routine and "sonido" not in cleaned:
            return Command("routine_execute", target=run_routine.group(1).strip())
        return None

    @staticmethod
    def _parse_iot_command(raw: str, cleaned: str) -> Command | None:
        if cleaned in {"conecta mqtt", "conecta el sistema iot", "conecta iot", "conecta el mqtt"}:
            return Command("iot_connect")
        if cleaned in {"desconecta mqtt", "desconecta el sistema iot", "desconecta iot", "desconecta el mqtt"}:
            return Command("iot_disconnect")
        if cleaned in {"dime que esp32 estan conectados", "que esp32 estan conectados", "dime que dispositivos estan conectados", "lista los dispositivos iot"}:
            return Command("iot_list_devices", arguments={"online_only": "conectados" in cleaned})
        register = re.match(r"^registra (?:un |el )?esp32 (?:llamado |como )?(.+?)(?: con capacidades (.+))?$", raw, re.IGNORECASE)
        if register:
            name, capability_text = register.groups()
            capabilities = tuple(item.strip().casefold() for item in (capability_text or "").split(",") if item.strip())
            return Command("iot_register_device", arguments={"name": name.strip(), "capabilities": capabilities})
        if cleaned in {"dime que automatizaciones iot tengo", "lista mis automatizaciones iot", "dime mis reglas iot"}:
            return Command("iot_list_rules")
        disable = re.match(r"^(?:desactiva|elimina) (?:la )?(?:automatizacion|regla)(?: de)?\s*(temperature|temperatura|humidity|humedad|ldr|luz)?(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if disable:
            sensor, reference = disable.groups()
            aliases = {"temperatura": "temperature", "humedad": "humidity", "luz": "ldr"}
            return Command("iot_disable_rule", arguments={"sensor": aliases.get(sensor, sensor), "reference": reference})
        if cleaned in {"deten las automatizaciones iot", "deten las reglas", "desactiva las reglas", "desactiva todas las reglas"}:
            return Command("iot_disable_all_rules")
        if cleaned in {"comprueba arduino cli", "comprueba platformio", "comprueba arduino cli y platformio"}:
            return Command("iot_check_tools")
        automation = re.match(
            r"^(?:avisame|avísame) si (?:la )?(temperature|temperatura|humidity|humedad|ldr|luz) (supera|es mayor que|baja de|es menor que|igual a) (\d+(?:[.,]\d+)?)(?: grados)?(?:\s+(?:del|de la|de)\s+(.+))?$",
            cleaned,
        )
        if automation:
            sensor, phrase, threshold, reference = automation.groups()
            aliases = {"temperatura": "temperature", "humedad": "humidity", "luz": "ldr"}
            operators = {"supera": ">", "es mayor que": ">", "baja de": "<", "es menor que": "<", "igual a": "=="}
            return Command("iot_create_rule", arguments={"sensor": aliases.get(sensor, sensor), "operator": operators[phrase], "threshold": float(threshold.replace(",", ".")), "reference": reference, "action": "notify"})
        alternate_automation = re.match(
            r"^si (?:la )?(temperature|temperatura|humidity|humedad|ldr|luz) (supera|es mayor que|baja de|es menor que) (\d+(?:[.,]\d+)?)(?: grados)? avisame(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned
        )
        if alternate_automation:
            sensor, phrase, threshold, reference = alternate_automation.groups()
            aliases = {"temperatura": "temperature", "humedad": "humidity", "luz": "ldr"}
            operators = {"supera": ">", "es mayor que": ">", "baja de": "<", "es menor que": "<"}
            return Command("iot_create_rule", arguments={"sensor": aliases.get(sensor, sensor), "operator": operators[phrase], "threshold": float(threshold.replace(",", ".")), "reference": reference, "action": "notify"})
        servo = re.match(r"^pon (?:el )?servo a (\d+(?:[.,]\d+)?) grados(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if servo:
            angle, reference = servo.groups()
            return Command("iot_set_servo", arguments={"reference": reference, "parameters": {"angle": float(angle.replace(",", "."))}})
        output = re.match(r"^(enciende|apaga) (?:el |la )?(led|luz|relay|rele|buzzer)(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if output:
            verb, target, reference = output.groups()
            action = {"led": "iot_set_led", "luz": "iot_set_led", "relay": "iot_set_relay", "rele": "iot_set_relay", "buzzer": "iot_set_buzzer"}[target]
            return Command(action, arguments={"reference": reference, "parameters": {"value": verb == "enciende"}})
        activate_device = re.match(r"^activa (?:el )?dispositivo(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if activate_device:
            return Command("iot_set_relay", arguments={"reference": activate_device.group(1), "parameters": {"value": True}})
        output_state = re.match(r"^(?:dime |muestrame )?(?:el )?estado (?:del |de la )?(led|luz|relay|rele|buzzer)(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if output_state:
            output, reference = output_state.groups()
            return Command("iot_get_state", arguments={"reference": reference, "output": "led" if output == "luz" else "relay" if output == "rele" else output})
        health = re.match(r"^(?:dime si |dime )?(?:el )?esp32(?:\s+(?:del|de la|de)\s+(.+))? (?:esta|está) (?:online|conectado)$", cleaned)
        if health:
            return Command("iot_get_state", arguments={"reference": health.group(1)})
        if cleaned.startswith("monitoriza") or cleaned.startswith("monitorea"):
            reference_match = re.search(r"(?:del|de la|de)\s+(.+)$", cleaned)
            return Command("iot_subscribe", arguments={"reference": reference_match.group(1) if reference_match else None})
        if cleaned in {"dime cuando fue la ultima lectura", "cuando fue la ultima lectura", "muestrame los ultimos datos del sensor"}:
            return Command("iot_get_telemetry", arguments={"sensor": None, "limit": 5 if "ultimos datos" in cleaned else 1})
        last = re.match(r"^(?:dime |muestrame )?(?:las )?(?:ultimas|últimas) (\d+) lecturas(?:\s+(?:del|de la|de)\s+(.+))?$", raw, re.IGNORECASE)
        if last:
            amount, reference = last.groups()
            return Command("iot_get_telemetry", arguments={"sensor": None, "reference": reference, "limit": min(int(amount), 20)})
        maximum = re.match(r"^(?:cual fue |dime )?(?:la )?(temperature|temperatura|humidity|humedad|ldr) maxima de hoy(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if maximum:
            sensor, reference = maximum.groups()
            return Command("iot_get_telemetry", arguments={"sensor": {"temperatura": "temperature", "humedad": "humidity"}.get(sensor, sensor), "reference": reference, "maximum_today": True})
        sensor_query = re.match(r"^(?:dime |cual es |cuanto es )?(?:la |el )?(temperature|temperatura|humidity|humedad|ldr|valor del ldr|luz)(?: actual)?(?:\s+(?:del|de la|de)\s+(.+))?$", cleaned)
        if sensor_query:
            sensor, reference = sensor_query.groups()
            aliases = {"temperatura": "temperature", "humedad": "humidity", "valor del ldr": "ldr", "luz": "ldr"}
            return Command("iot_get_telemetry", arguments={"sensor": aliases.get(sensor, sensor), "reference": reference, "limit": 1})
        if cleaned in {"dime el estado del esp32", "dime el estado del dispositivo", "dime si el esp32 esta conectado"}:
            return Command("iot_get_state")
        return None

    def _parse_cyberseg_command(self, raw: str, cleaned: str) -> Command | None:
        if self._cyberseg is None or "cyberseg" not in cleaned:
            return None
        if any(phrase in cleaned for phrase in ("estado de cyberseg", "estado cyberseg", "cyberseg esta activo", "cyberseg está activo")):
            return Command("cyberseg_status")
        if (
            any(phrase in cleaned for phrase in ("amenazas de cyberseg", "tipos de ataques", "cobertura cyberseg", "entrenamiento cyberseg"))
            or ("entrenamiento" in cleaned and "cyberseg" in cleaned)
        ):
            return Command("cyberseg_threat_coverage")
        if any(phrase in cleaned for phrase in ("alertas de cyberseg", "alertas cyberseg", "muestra cyberseg")):
            limit = 10 if any(value in cleaned for value in ("diez", "10")) else 5
            return Command("cyberseg_alerts", arguments={"limit": limit})
        if cleaned.startswith(("revisa cyberseg", "analiza cyberseg")):
            return Command("cyberseg_alerts", arguments={"limit": 10})
        if re.match(r"^(?:inicia|activa|iniciar) (?:la )?(?:captura )?(?:de )?cyberseg$", cleaned):
            return Command("cyberseg_start_capture")
        if re.match(r"^(?:deten|detiene|desactiva|parar) (?:la )?(?:captura )?(?:de )?cyberseg$", cleaned):
            return Command("cyberseg_stop_capture")
        return None

    @staticmethod
    def _parse_code_command(raw: str, cleaned: str) -> Command | None:
        vscode_project = re.match(r"^abre (?:mi |este )?proyecto(?:\s+(.+?))? en (?:vs code|visual studio code)$", raw, re.IGNORECASE)
        if vscode_project:
            return Command("code_open_vscode", arguments={"project": vscode_project.group(1).strip() if vscode_project.group(1) else None})
        project = re.match(r"^abre (?:mi |este )?proyecto(?:\s+(.+))?$", raw, re.IGNORECASE)
        if project:
            return Command("code_scan_project", arguments={"project": project.group(1).strip() if project.group(1) else None})
        if cleaned in {"analiza este proyecto", "analiza la arquitectura de este proyecto"}:
            return Command("code_scan_project")
        if cleaned in {"dime como esta organizado", "muestrame la estructura", "analiza la arquitectura de este proyecto"}:
            return Command("code_architecture")
        if cleaned in {"dime que stack usa", "que stack usa este proyecto"}:
            return Command("code_architecture")
        if cleaned in {"dime que dependencias usa este proyecto", "dime las dependencias"}:
            return Command("code_dependencies")
        if cleaned in {"ejecuta los tests", "ejecuta las pruebas", "ejecuta pytest"}:
            return Command("code_run_tests")
        if cleaned in {"ejecuta el build", "ejecuta build"}:
            return Command("code_run_build")
        if cleaned in {"ejecuta lint", "ejecuta el lint"}:
            return Command("code_run_lint")
        if cleaned in {"revisa mis cambios", "revisa este codigo por seguridad", "revisa este código por seguridad"}:
            return Command("code_review")
        if cleaned in {"muestrame el diff", "muestra el diff"}:
            return Command("code_diff")
        if cleaned in {"dime que archivos modificaste", "muestrame que archivos modificaste"}:
            return Command("code_changed_files")
        if cleaned in {"aplica el plan", "aplica el parche", "aplica los cambios propuestos"}:
            return Command("code_apply_patch")
        if cleaned in {"crea el proyecto propuesto", "construye el proyecto propuesto", "aplica el proyecto propuesto"}:
            return Command("code_project_apply")
        project = re.match(r"^(?:crea|construye|genera) (?:un )?proyecto(?:\s+(?:de|para))?\s+(.+)$", raw, re.IGNORECASE)
        if project:
            return Command("code_project_plan", arguments={"objective": project.group(1).strip()})
        open_file = re.match(r"^abre (?:el |este )?archivo\s+(.+?)(?: en (?:vs code|visual studio code))?$", raw, re.IGNORECASE)
        if open_file:
            return Command("code_open_vscode", arguments={"target": open_file.group(1).strip()})
        search = re.match(r"^(?:busca|encuentra) (?:donde esta |donde se |referencias a )?(.+)$", raw, re.IGNORECASE)
        if search and any(marker in cleaned for marker in ("service", "login", "jwt", "prisma", "componente", "referencias", "implementado")):
            return Command("code_search", arguments={"query": search.group(1).strip(), "symbols": "referencias" not in cleaned})
        where = re.match(r"^dime donde esta (?:implementado )?(.+)$", raw, re.IGNORECASE)
        if where:
            return Command("code_search", arguments={"query": where.group(1).strip(), "symbols": True})
        explain = re.match(r"^(?:explicame|explícame|revisa) (?:este |el )?(?:archivo|metodo|método)?\s*(.+)$", raw, re.IGNORECASE)
        if explain and explain.group(1).strip():
            return Command("code_explain", arguments={"target": explain.group(1).strip()})
        if cleaned in {"corrige este error", "corrige el primero", "corrige el error anterior"}:
            return Command("code_diagnostics")
        if cleaned.startswith(("corrige", "crea un servicio", "crea un test", "crea una clase", "agrega un endpoint", "crea un modulo", "crea un módulo")):
            return Command("code_plan_change", arguments={"objective": raw})
        commit = re.match(r"^crea un commit con (?:estos )?cambios(?: con (?:el )?mensaje [\"']?(.+?)[\"']?)?$", raw, re.IGNORECASE)
        if commit:
            return Command("code_commit", arguments={"message": commit.group(1).strip() if commit.group(1) else None})
        return None

    def execute(self, command: Command) -> CommandResult:
        if command.action not in ALLOWED_COMMANDS:
            return CommandResult(False, "Esa acción todavía no está permitida.")
        handler = self._handlers.get(command.action)
        return handler(command) if handler else CommandResult(False, "Esa acción todavía no está implementada.")

    def cancel_pending_actions(self) -> None:
        if self._active_queue is not None:
            self._active_queue.cancel()
        if self._terminal_router is not None:
            self._terminal_router.cancel_pending_actions()

    def _automation_command(self, target: str, text: str) -> Command:
        steps = (
            {"action": "open_application", "target": target}, {"action": "wait_for_window", "target": target},
            {"action": "focus_window", "target": target}, {"action": "type_text", "text": text},
        )
        return Command("automation_sequence", arguments={"steps": steps, "sensitive": self._active_window_is_sensitive()})

    @staticmethod
    def _clean_written_text(text: str) -> str:
        return text.strip().strip('"')

    @staticmethod
    def _is_screen_request(text: str) -> bool:
        phrases = (
            "mira mi pantalla",
            "captura la pantalla",
            "captura esta ventana",
            "captura la ventana",
            "analiza lo que tengo abierto",
            "mira esta ventana",
            "mira mi error",
            "dime que aparece en pantalla",
            "analiza esta ventana",
        )
        return any(phrase in text for phrase in phrases)

    def _active_window_is_sensitive(self) -> bool:
        title = self._active_window_title()
        return is_sensitive_window(title)

    def _active_window_title(self) -> str | None:
        try:
            active = self._windows.get_active_window()
            return active.title if active else None
        except Exception:
            return None

    def _handle_set_volume(self, command: Command) -> CommandResult:
        if "mute" in command.arguments:
            return self._audio.set_mute(bool(command.arguments["mute"]))
        level = command.arguments.get("level")
        return self._audio.set_volume(level) if isinstance(level, int) else CommandResult(False, "Indica un nivel de volumen entre 0 y 100 %.")

    def _handle_open_url(self, command: Command) -> CommandResult:
        return self._browser.open_site(command.target) if command.target else self._browser.open_url(str(command.arguments.get("url", "")))

    def _handle_trusted_browser_login(self, _command: Command) -> CommandResult:
        result = self._browser.open_url("https://accounts.google.com/")
        return CommandResult(result.success, "Abrí Google en tu perfil normal de Chrome." if result.success else result.message)

    @staticmethod
    def _parse_trusted_browser_login(cleaned: str) -> Command | None:
        if re.match(r"^(?:inicia(?:r)? sesion|accede) (?:en |a )?(?:google|gmail)$", cleaned):
            return Command("browser_trusted_login")
        return None

    @staticmethod
    def _vision_result(operation: Callable[[], str]) -> CommandResult:
        try:
            return CommandResult(True, operation())
        except Exception as error:
            return CommandResult(False, str(error))

    def _handle_wait_for_window(self, command: Command) -> CommandResult:
        try:
            window = self._windows.wait_for_window(command.target)
        except Exception as error:
            return CommandResult(False, str(error))
        return CommandResult(True, f"Ventana detectada: {window.title}.") if window else CommandResult(False, "No apareció la ventana a tiempo.")

    def _handle_move_mouse(self, command: Command) -> CommandResult:
        x, y = command.arguments.get("x"), command.arguments.get("y")
        return self._mouse.move_to(x, y) if isinstance(x, int) and isinstance(y, int) else CommandResult(False, "Indica coordenadas válidas para el mouse.")

    def _handle_mouse_position(self, _command: Command) -> CommandResult:
        x, y = self._mouse.get_position()
        return CommandResult(True, f"El mouse está en {x}, {y}.")

    def _handle_mouse_click(self, command: Command) -> CommandResult:
        return self._mouse.click(self._integer_argument(command, "x"), self._integer_argument(command, "y"))

    def _handle_mouse_double_click(self, command: Command) -> CommandResult:
        return self._mouse.double_click(self._integer_argument(command, "x"), self._integer_argument(command, "y"))

    def _handle_mouse_right_click(self, command: Command) -> CommandResult:
        return self._mouse.right_click(self._integer_argument(command, "x"), self._integer_argument(command, "y"))

    @staticmethod
    def _integer_argument(command: Command, name: str) -> int | None:
        value = command.arguments.get(name)
        return value if isinstance(value, int) else None

    def _handle_scroll(self, command: Command) -> CommandResult:
        amount = command.arguments.get("amount")
        return self._mouse.scroll(amount) if isinstance(amount, int) else CommandResult(False, "Indica una dirección para el desplazamiento.")

    def _handle_type_text(self, command: Command) -> CommandResult:
        text = command.arguments.get("text")
        try:
            if self._windows.get_active_window() is None:
                return CommandResult(False, "No encontré una ventana activa para escribir.")
        except Exception:
            return CommandResult(False, "No pude comprobar la ventana activa antes de escribir.")
        return self._keyboard.type_text(text) if isinstance(text, str) else CommandResult(False, "Indica el texto que quieres escribir.")

    def _handle_automation_sequence(self, command: Command) -> CommandResult:
        raw_steps = command.arguments.get("steps")
        if not isinstance(raw_steps, tuple):
            return CommandResult(False, "La automatización no tiene acciones válidas.")
        queue = ActionQueue()
        for step in raw_steps:
            if not isinstance(step, dict) or not isinstance(step.get("action"), str):
                return CommandResult(False, "La automatización contiene una acción inválida.")
            action_type = step["action"]
            if not is_registered_action(action_type):
                return CommandResult(False, "La automatización contiene una acción no registrada.")
            target = step.get("target")
            queue.enqueue(Action(action_type, target if isinstance(target, str) else None, dict(step), SecurityLevel.CONFIRMATION))
        self._active_queue = queue
        messages: list[str] = []
        while (action := queue.pop_next()) is not None:
            arguments = dict(action.parameters)
            arguments.pop("action", None)
            arguments.pop("target", None)
            result = self.execute(Command(action.action_type, action.target, arguments))
            if not result.success:
                queue.cancel()
                return CommandResult(False, result.message)
            messages.append(result.message)
        return CommandResult(True, " ".join(messages))

    def _handle_memory_remember(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        content = command.arguments.get("content")
        if not isinstance(content, str):
            return CommandResult(False, "Indica qué quieres que recuerde.")
        memory = self._memory.remember(content)
        if memory is None:
            return CommandResult(False, "La memoria permanente está desactivada.")
        return CommandResult(True, "Lo recordaré para próximas sesiones.")

    def _handle_memory_recall(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        query = command.arguments.get("query")
        if not isinstance(query, str):
            return CommandResult(False, "Indica qué recuerdo quieres consultar.")
        memories = self._memory.recall(query)
        if not memories:
            return CommandResult(True, "No encontré recuerdos persistentes relacionados.")
        return CommandResult(True, "\n".join(f"- {memory.content}" for memory in memories))

    def _handle_memory_forget(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        query = command.arguments.get("query")
        if not isinstance(query, str):
            return CommandResult(False, "Indica qué recuerdo quieres eliminar.")
        result = self._memory.forget(query)
        if result.deleted is not None:
            return CommandResult(True, "Eliminé ese recuerdo persistente.")
        if not result.candidates:
            return CommandResult(True, "No encontré un recuerdo que coincida exactamente.")
        options = "; ".join(memory.content for memory in result.candidates[:3])
        return CommandResult(False, f"Encontré {len(result.candidates)} recuerdos relacionados. Sé más específico: {options}")

    def _handle_memory_update(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        query, content = command.arguments.get("query"), command.arguments.get("content")
        if not isinstance(query, str) or not isinstance(content, str):
            return CommandResult(False, "Indica el recuerdo y el nuevo dato.")
        updated = self._memory.update(query, content)
        return CommandResult(True, "Actualicé ese recuerdo.") if updated else CommandResult(False, "No encontré un único recuerdo seguro para actualizar.")

    def _handle_memory_explain(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        query = command.arguments.get("query")
        return CommandResult(True, self._memory.why(query)) if isinstance(query, str) else CommandResult(False, "Indica qué recuerdo quieres revisar.")

    def _handle_memory_when(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        query = command.arguments.get("query")
        return CommandResult(True, self._memory.when(query)) if isinstance(query, str) else CommandResult(False, "Indica qué recuerdo quieres revisar.")

    def _handle_memory_stats(self, _command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        stats = self._memory.stats()
        kinds = ", ".join(f"{kind}: {count}" for kind, count in stats["by_type"].items()) or "sin recuerdos"
        return CommandResult(True, f"Tengo {stats['total']} recuerdos ({kinds}) y {stats['vectors']} índices semánticos locales.")

    def _handle_memory_export(self, command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = Path(self._memory.repository.path).parent / "exports" / f"jarvis-memory-{stamp}.json"
        query = command.arguments.get("query")
        path = self._memory.export(str(destination), query if isinstance(query, str) else None)
        return CommandResult(True, f"Exporté tus recuerdos locales en {path}.")

    def _handle_memory_clear_all(self, _command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        count = self._memory.clear_all()
        return CommandResult(True, f"Eliminé {count} recuerdos persistentes.")

    def _handle_memory_last_session(self, _command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        return CommandResult(True, self._memory.last_session())

    def _handle_memory_backup(self, _command: Command) -> CommandResult:
        if self._memory is None:
            return CommandResult(False, "La memoria permanente no está configurada.")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        directory = Path(self._memory.repository.path).parent / "backups"
        destination = directory / f"jarvis-{stamp}.db"
        return CommandResult(True, f"Copia de seguridad creada en {self._memory.backup(str(destination))}.")

    def _code(self) -> CodeAgent:
        if self._code_agent is None:
            raise ValueError("Code Agent no está configurado.")
        return self._code_agent

    def _iot(self) -> IoTAgent:
        if self._iot_agent is None:
            raise ValueError("IoT Agent no está configurado.")
        return self._iot_agent

    def _cyberseg_client(self) -> CyberSegClient:
        if self._cyberseg is None:
            raise ValueError("CyberSeg no está configurado.")
        return self._cyberseg

    @staticmethod
    def _iot_result(operation: Callable[[], str]) -> CommandResult:
        try:
            return CommandResult(True, operation())
        except (OSError, ValueError, ConnectionError, RuntimeError) as error:
            return CommandResult(False, str(error))

    @staticmethod
    def _cyberseg_result(operation: Callable[[], str]) -> CommandResult:
        try:
            return CommandResult(True, operation())
        except (CyberSegClientError, OSError, ValueError, ConnectionError, RuntimeError) as error:
            return CommandResult(False, str(error))

    @staticmethod
    def _code_result(operation: Callable[[], str]) -> CommandResult:
        try:
            return CommandResult(True, operation())
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_scan(self, _command: Command) -> CommandResult:
        try:
            requested = _command.arguments.get("project")
            project = self._code().analyze_project(requested if isinstance(requested, str) else None)
            stack = ", ".join([*project.frameworks, *project.languages]) or "no detectado"
            return CommandResult(True, f"Proyecto {project.name} analizado. Stack: {stack}. Archivos indexados: {len(project.files)}.")
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_search(self, command: Command) -> CommandResult:
        query = command.arguments.get("query")
        if not isinstance(query, str):
            return CommandResult(False, "Indica qué símbolo o texto quieres buscar.")
        try:
            matches = self._code().search_code(query, symbols=command.arguments.get("symbols") is True)
            if not matches:
                return CommandResult(True, "No encontré coincidencias de código.")
            root = self._code()._project().root_path
            return CommandResult(True, "\n".join(f"- {item.path.relative_to(root)}:{item.line} {item.snippet}" for item in matches[:12]))
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_explain(self, command: Command) -> CommandResult:
        target = command.arguments.get("target")
        return self._code_result(lambda: self._code().explain_code(target)) if isinstance(target, str) else CommandResult(False, "Indica el archivo o símbolo que quieres explicar.")

    def _handle_code_plan(self, command: Command) -> CommandResult:
        objective = command.arguments.get("objective")
        if not isinstance(objective, str):
            return CommandResult(False, "Indica el cambio de código que quieres planear.")
        try:
            plan = self._code().plan_change(objective)
            return CommandResult(True, self._code().preview_plan(plan.id) + "\n\nDi 'Jarvis aplica el plan' para solicitar la aplicación confirmada.")
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_apply(self, _command: Command) -> CommandResult:
        try:
            result = self._code().apply_change()
            return CommandResult(True, result.message + "\n" + result.diff)
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_project_plan(self, command: Command) -> CommandResult:
        objective = command.arguments.get("objective")
        if not isinstance(objective, str):
            return CommandResult(False, "Indica qué proyecto quieres construir.")
        try:
            plan = self._code().plan_project(objective)
            return CommandResult(True, self._code().preview_project(plan.id) + "\n\nDi 'Jarvis crea el proyecto propuesto' para solicitar la creación confirmada.")
        except (OSError, ValueError, RuntimeError) as error:
            return CommandResult(False, str(error))

    def _handle_project_apply(self, _command: Command) -> CommandResult:
        try:
            result = self._code().apply_project()
            return CommandResult(True, result.message + "\n" + result.diff)
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_vscode(self, command: Command) -> CommandResult:
        target = command.arguments.get("target")
        project = command.arguments.get("project")
        try:
            if isinstance(project, str):
                self._code().analyze_project(project)
            return self._code().open_vscode(target if isinstance(target, str) else None)
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_diagnostics(self, _command: Command) -> CommandResult:
        try:
            output = self._code().terminal.last_output().message
            diagnostics = self._code().diagnostics(output)
            if not diagnostics:
                return CommandResult(True, "No hay un error reciente de terminal para analizar.")
            return CommandResult(True, "\n".join(f"- {item.path or 'salida'}:{item.line or '-'} {item.message}" for item in diagnostics[:5]))
        except (OSError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_code_commit(self, command: Command) -> CommandResult:
        message = command.arguments.get("message")
        return self._code_result(lambda: self._code().create_commit(message if isinstance(message, str) else None))

    def _handle_iot_list_devices(self, command: Command) -> CommandResult:
        return self._iot_result(lambda: self._iot().list_devices(online_only=command.arguments.get("online_only") is True))

    def _handle_cyberseg_alerts(self, command: Command) -> CommandResult:
        limit = command.arguments.get("limit", 5)
        return self._cyberseg_result(
            lambda: enrich_alerts(self._cyberseg_client().recent_alerts(limit if isinstance(limit, int) else 5))
        )

    def _handle_iot_get_state(self, command: Command) -> CommandResult:
        reference, output = command.arguments.get("reference"), command.arguments.get("output")
        return self._iot_result(lambda: self._iot().get_device_state(reference if isinstance(reference, str) else None, output if isinstance(output, str) else None))

    def _handle_iot_get_telemetry(self, command: Command) -> CommandResult:
        sensor, reference = command.arguments.get("sensor"), command.arguments.get("reference")
        limit = command.arguments.get("limit", 1)
        maximum = command.arguments.get("maximum_today") is True
        return self._iot_result(lambda: self._iot().get_telemetry(
            sensor if isinstance(sensor, str) else None, reference if isinstance(reference, str) else None,
            limit=limit if isinstance(limit, int) else 1, maximum_today=maximum,
        ))

    def _handle_iot_command(self, command: Command) -> CommandResult:
        actions = {"iot_set_led": "set_led", "iot_set_relay": "set_relay", "iot_set_servo": "set_servo", "iot_set_buzzer": "set_buzzer"}
        reference, parameters = command.arguments.get("reference"), command.arguments.get("parameters")
        return self._iot_result(lambda: self._iot().send_command(
            reference if isinstance(reference, str) else None, actions[command.action], parameters if isinstance(parameters, dict) else {},
        ))

    def _handle_iot_subscribe(self, command: Command) -> CommandResult:
        reference = command.arguments.get("reference")
        return self._iot_result(lambda: self._iot().subscribe(reference if isinstance(reference, str) else None))

    def _handle_iot_create_rule(self, command: Command) -> CommandResult:
        sensor, operator, threshold = command.arguments.get("sensor"), command.arguments.get("operator"), command.arguments.get("threshold")
        reference, action = command.arguments.get("reference"), command.arguments.get("action")
        if not isinstance(sensor, str) or not isinstance(operator, str) or not isinstance(threshold, (int, float)):
            return CommandResult(False, "La automatización IoT no tiene una condición válida.")
        return self._iot_result(lambda: self._iot().create_rule(
            reference if isinstance(reference, str) else None, sensor, operator, float(threshold), action if isinstance(action, str) else "notify",
        ))

    def _handle_iot_register(self, command: Command) -> CommandResult:
        name, capabilities = command.arguments.get("name"), command.arguments.get("capabilities")
        if not isinstance(name, str):
            return CommandResult(False, "Indica el nombre del ESP32 que quieres registrar.")
        values = capabilities if isinstance(capabilities, tuple) and all(isinstance(item, str) for item in capabilities) else ()
        return self._iot_result(lambda: self._iot().register_esp32(name, values))

    def _handle_iot_list_rules(self, command: Command) -> CommandResult:
        reference = command.arguments.get("reference")
        return self._iot_result(lambda: self._iot().list_rules(reference if isinstance(reference, str) else None))

    def _handle_iot_disable_rules(self, command: Command) -> CommandResult:
        reference, sensor = command.arguments.get("reference"), command.arguments.get("sensor")
        return self._iot_result(lambda: self._iot().disable_rules(reference if isinstance(reference, str) else None, sensor if isinstance(sensor, str) else None))

    def _handle_iot_check_tools(self, _command: Command) -> CommandResult:
        terminal = getattr(self._terminal_router, "_manager", None)
        return self._iot_result(lambda: self._iot().check_firmware_tools(terminal))

    def _handle_orchestrator_agents(self, _command: Command) -> CommandResult:
        if self._agent_registry is None:
            return CommandResult(False, "El registro de agentes no está disponible.")
        return CommandResult(True, "Agentes disponibles: " + ", ".join(self._agent_registry.names()) + ".")

    def _handle_orchestrator_agent_status(self, _command: Command) -> CommandResult:
        if self._agent_registry is None:
            return CommandResult(False, "El registro de agentes no está disponible.")
        status = self._agent_registry.status()
        return CommandResult(True, "Estado de agentes:\n" + "\n".join(f"- {name}: {value}" for name, value in status.items()))

    def _handle_orchestrator_set_mode(self, command: Command) -> CommandResult:
        if self._orchestrator is None or command.target is None:
            return CommandResult(False, "El orquestador no está disponible.")
        try:
            return CommandResult(True, self._orchestrator.set_mode(command.target))
        except ValueError as error:
            return CommandResult(False, str(error))

    def _handle_orchestrator_goal(self, command: Command) -> CommandResult:
        if self._orchestrator is None:
            return CommandResult(False, "El orquestador no está disponible.")
        goal = command.arguments.get("goal")
        if not isinstance(goal, str) or not goal.strip():
            return CommandResult(False, "Indica el objetivo que quieres coordinar.")
        result = self._orchestrator.process_goal_sync(goal)
        return CommandResult(result.success, result.summary)

    def _handle_orchestrator_status(self, _command: Command) -> CommandResult:
        return CommandResult(False, "El orquestador no está disponible.") if self._orchestrator is None else CommandResult(True, self._orchestrator.status())

    def _handle_orchestrator_cancel(self, _command: Command) -> CommandResult:
        return CommandResult(False, "El orquestador no está disponible.") if self._orchestrator is None else CommandResult(True, self._orchestrator.cancel())

    def _handle_automation_list_engine(self, _command: Command) -> CommandResult:
        if self._automation_engine is None:
            return CommandResult(False, "Automation Engine no está disponible.")
        items = self._automation_engine.list()
        if not items:
            return CommandResult(True, "No tienes automatizaciones v1.0 guardadas.")
        return CommandResult(True, "Automatizaciones:\n" + "\n".join(f"- {item.name}: {'activa' if item.enabled else 'desactivada'}" for item in items))

    def _handle_automation_create_engine(self, command: Command) -> CommandResult:
        if self._automation_engine is None:
            return CommandResult(False, "Automation Engine no está disponible.")
        try:
            kind, name = str(command.arguments["kind"]), str(command.arguments["name"])
            if kind == "programming":
                automation = Automation(name, ManualTrigger(), (), (AutomationAction("system", "system.open_application", {"application": "vscode"}),))
            elif kind == "daily_notice":
                automation = Automation(name, TimeTrigger(str(command.arguments["time"])), (), (AutomationAction("automation", "notify", {"message": f"Automatización '{name}' activada."}),))
            elif kind == "device_offline":
                device = str(command.arguments["device"])
                automation = Automation(name, EventTrigger("DEVICE_OFFLINE", {"device_id": device}), (), (AutomationAction("automation", "notify", {"message": f"El ESP32 {device} se desconectó."}),))
            else:
                return CommandResult(False, "Tipo de automatización no registrado.")
            saved = self._automation_engine.create(automation)
            return CommandResult(True, f"Automatización guardada: {saved.name}.")
        except (KeyError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_automation_enable_engine(self, command: Command) -> CommandResult:
        if self._automation_engine is None or command.target is None:
            return CommandResult(False, "Automation Engine no está disponible.")
        return CommandResult(True, "Automatización activada.") if self._automation_engine.set_enabled(command.target, True) else CommandResult(False, "No encontré esa automatización.")

    def _handle_automation_disable_engine(self, command: Command) -> CommandResult:
        if self._automation_engine is None or command.target is None:
            return CommandResult(False, "Automation Engine no está disponible.")
        return CommandResult(True, "Automatización desactivada.") if self._automation_engine.set_enabled(command.target, False) else CommandResult(False, "No encontré esa automatización.")

    def _handle_automation_run_engine(self, command: Command) -> CommandResult:
        if self._automation_engine is None or command.target is None:
            return CommandResult(False, "Automation Engine no está disponible.")
        try:
            import asyncio
            result = asyncio.run(self._automation_engine.run_manual(command.target))
            return CommandResult(result.success, result.summary)
        except (RuntimeError, ValueError) as error:
            return CommandResult(False, str(error))

    def _handle_reminder_create(self, command: Command) -> CommandResult:
        if self._reminders is None:
            return CommandResult(False, "El scheduler local no está configurado.")
        request = command.arguments.get("request")
        if not isinstance(request, str):
            return CommandResult(False, "Indica qué y cuándo debo recordártelo.")
        try:
            reminder = self._reminders.create_from_text(request, datetime.now(ZoneInfo(self._reminders.timezone_name)))
        except ValueError as error:
            return CommandResult(False, str(error))
        time = reminder.trigger_at.astimezone(ZoneInfo(self._reminders.timezone_name)).strftime("%d/%m a las %H:%M")
        return CommandResult(True, f"Recordatorio guardado para {time}: {reminder.title}.")

    def _handle_reminder_list(self, _command: Command) -> CommandResult:
        if self._reminders is None:
            return CommandResult(False, "El scheduler local no está configurado.")
        items = self._reminders.list_pending()
        if not items:
            return CommandResult(True, "No tienes recordatorios pendientes.")
        zone = ZoneInfo(self._reminders.timezone_name)
        lines = [f"{index}. {item.title} — {item.trigger_at.astimezone(zone):%d/%m %H:%M}" for index, item in enumerate(items[:10], 1)]
        return CommandResult(True, "Recordatorios pendientes:\n" + "\n".join(lines))

    def _handle_reminder_list_today(self, _command: Command) -> CommandResult:
        if self._reminders is None:
            return CommandResult(False, "El scheduler local no está configurado.")
        items = self._reminders.list_today(datetime.now(ZoneInfo(self._reminders.timezone_name)))
        if not items:
            return CommandResult(True, "No tienes recordatorios pendientes para hoy.")
        return CommandResult(True, "Pendiente hoy:\n" + "\n".join(f"- {item.title}" for item in items))

    def _handle_reminder_cancel(self, command: Command) -> CommandResult:
        if self._reminders is None:
            return CommandResult(False, "El scheduler local no está configurado.")
        query = command.arguments.get("query")
        if not isinstance(query, str):
            return CommandResult(False, "Indica qué recordatorio quieres cancelar.")
        reminder, matches = self._reminders.cancel(query)
        if reminder is not None:
            return CommandResult(True, f"Cancelé el recordatorio: {reminder.title}.")
        if not matches:
            return CommandResult(False, "No encontré ese recordatorio pendiente.")
        return CommandResult(False, f"Encontré {len(matches)} recordatorios. Indica un nombre más específico.")

    def _handle_reminder_complete(self, command: Command) -> CommandResult:
        if self._reminders is None:
            return CommandResult(False, "El scheduler local no está configurado.")
        query = command.arguments.get("query")
        if not isinstance(query, str):
            return CommandResult(False, "Indica qué tarea quieres completar.")
        reminder, matches = self._reminders.complete(query)
        if reminder is not None:
            return CommandResult(True, f"Marqué como completado: {reminder.title}.")
        return CommandResult(False, "No encontré un recordatorio único con ese nombre." if not matches else "Hay varios recordatorios similares; sé más específico.")

    def _handle_routine_begin(self, command: Command) -> CommandResult:
        if self._routines is None or not command.target:
            return CommandResult(False, "El gestor de rutinas no está configurado.")
        self._routines.begin(command.target)
        return CommandResult(True, f"Rutina '{command.target}' iniciada. Di, por ejemplo: Jarvis agrega abre VS Code; luego di Jarvis guarda rutina.")

    def _handle_routine_add(self, command: Command) -> CommandResult:
        if self._routines is None:
            return CommandResult(False, "El gestor de rutinas no está configurado.")
        instruction = command.arguments.get("instruction")
        if not isinstance(instruction, str):
            return CommandResult(False, "Indica una acción segura para la rutina.")
        action = self._routines.add_action_from_text(instruction)
        if action is None:
            return CommandResult(False, "Solo puedes añadir aperturas de aplicaciones o carpetas registradas a la rutina actual.")
        return CommandResult(True, "Acción segura añadida a la rutina.")

    def _handle_routine_save(self, _command: Command) -> CommandResult:
        if self._routines is None:
            return CommandResult(False, "El gestor de rutinas no está configurado.")
        routine = self._routines.save_draft()
        return CommandResult(True, f"Rutina guardada: {routine.name}.") if routine else CommandResult(False, "La rutina no tiene acciones seguras para guardar.")

    def _handle_routine_execute(self, command: Command) -> CommandResult:
        if self._routines is None or not command.target:
            return CommandResult(False, "Indica qué rutina quieres ejecutar.")
        routine = self._routines.get(command.target)
        if routine is None:
            return CommandResult(False, "No encontré esa rutina.")
        if not routine.actions:
            return CommandResult(False, "Esa rutina no contiene acciones.")
        queue = ActionQueue()
        for action in routine.actions:
            if not is_registered_action(action.action_type):
                return CommandResult(False, "La rutina contiene una acción no registrada y fue bloqueada.")
            queue.enqueue(action)
        messages: list[str] = []
        while (action := queue.pop_next()) is not None:
            result = self.execute(Command(action.action_type, action.target, dict(action.parameters)))
            if not result.success:
                queue.cancel()
                return CommandResult(False, result.message)
            messages.append(result.message)
        return CommandResult(True, f"Ejecutando rutina: {routine.name}. " + " ".join(messages))
