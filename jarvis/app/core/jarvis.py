from __future__ import annotations

import logging
from dataclasses import dataclass

from app.ai.provider import AIProvider, AIProviderError
from app.commands.base import Command, CommandName, RouteType
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.memory.manager import MemoryManager
from app.memory.models import MemoryPolicy
from app.security.confirmation import ConfirmationAnswer, ConfirmationManager
from app.security.permissions import OperationMode, PermissionManager, SecurityLevel
from app.experience.states import JarvisVisualState


@dataclass(frozen=True, slots=True)
class ProcessResult:
    response: str
    should_exit: bool = False


class Jarvis:
    def __init__(
        self,
        provider: AIProvider,
        conversation: ConversationManager,
        router: CommandRouter,
        logger: logging.Logger,
        permissions: PermissionManager | None = None,
        confirmations: ConfirmationManager | None = None,
        memory: MemoryManager | None = None,
        user_manager=None,
        experience=None,
    ) -> None:
        self._provider = provider
        self._conversation = conversation
        self._router = router
        self._logger = logger
        self._permissions = permissions or PermissionManager()
        self._confirmations = confirmations or ConfirmationManager()
        self._memory = memory
        self._users = user_manager
        self._experience = experience

    def process(self, text: str) -> ProcessResult:
        if self._experience is not None:
            self._experience.set_state(JarvisVisualState.PROCESSING, transcript=text[:500])
        route = self._router.route(text)
        if route.type is RouteType.COMMAND and route.command is CommandName.CANCEL:
            self._confirmations.clear()
            self._router.cancel_pending_actions()
            return self._finish("Acciones pendientes canceladas. El control de emergencia está activo.")

        # Las paradas IoT tienen prioridad sobre una confirmación pendiente: no
        # deben quedar bloqueadas detrás de un relay, un servo u otra acción.
        if route.parsed_command is not None and route.parsed_command.action in {"iot_disconnect", "iot_disable_all_rules", "orchestrator_cancel"}:
            self._confirmations.clear()
            return self._execute(route.parsed_command)

        pending = self._confirmations.pending
        if pending is not None:
            return self._process_confirmation(text, pending.command)

        if route.type is RouteType.COMMAND and route.command is CommandName.EXIT:
            self._logger.info("Exit command received")
            return self._finish("Cerrando el sistema. Hasta luego.", should_exit=True)

        if route.type in {RouteType.COMMAND, RouteType.TERMINAL_COMMAND}:
            if route.parsed_command is None:
                return self._finish("No entendí un comando seguro para esa petición.")
            return self._process_command(route.parsed_command)

        self._conversation.add_user_message(text)
        if self._memory is not None and self._memory.policy is MemoryPolicy.SMART:
            self._memory.remember(text, memory_type="conversation", source="conversation", importance=0.35)
        if self._memory is not None:
            self._memory.update_working(current_topic=text[:180], last_conversation=text[:180])
        self._logger.info("Conversation transcription received")
        try:
            history = self._conversation.messages()
            if self._memory is not None:
                context = self._memory.build_context(text)
                if context:
                    history = [{"role": "system", "content": context}, *history]
            response = self._provider.generate_response(history)
        except AIProviderError as error:
            self._logger.error("AI provider error: %s", error)
            return self._finish(f"No pude procesar la consulta. {error}", error=True)
        self._conversation.add_assistant_message(response)
        if self._memory is not None:
            self._memory.update_working(last_conversation=response[:180])
        self._logger.info("AI response generated")
        return self._finish(response)

    def _finish(self, response: str, *, should_exit: bool = False, error: bool = False) -> ProcessResult:
        if self._experience is not None:
            self._experience.set_state(JarvisVisualState.ERROR if error else JarvisVisualState.SPEAKING, response=response[:700])
        return ProcessResult(response, should_exit=should_exit)

    def shutdown(self) -> None:
        self._conversation.close()

    def _process_command(self, command: Command) -> ProcessResult:
        if self._experience is not None:
            agent = "browser" if command.action.startswith("browser_") else "code" if command.action.startswith("code_") else "terminal" if command.action.startswith("terminal_") else "iot" if command.action.startswith("iot_") else "system"
            self._experience.set_state(JarvisVisualState.EXECUTING, agent=agent, action=command.action)
        if self._users is not None and command.action not in {"user_active", "user_list", "user_switch", "user_lock"}:
            capability = "terminal" if command.action.startswith("terminal_") else "code" if command.action.startswith("code_") else "iot" if command.action.startswith("iot_") else "cyberseg" if command.action.startswith("cyberseg_") else "automation" if command.action.startswith("automation_") else "memory"
            modifying = command.action.startswith(("terminal_", "code_", "iot_", "cyberseg_start_", "automation_"))
            if not self._users.allows(capability, modifying=modifying):
                return self._finish("Esta acción no está permitida para tu perfil.", error=True)
        decision = self._permissions.evaluate(command)
        if decision.level in {SecurityLevel.RESTRICTED, SecurityLevel.BLOCKED}:
            return self._finish(decision.message or "Esa acción todavía no está permitida.", error=True)
        if decision.level in {SecurityLevel.CONFIRMATION, SecurityLevel.SENSITIVE}:
            prompt = self._confirmation_prompt(command)
            self._confirmations.request(command, prompt)
            self._logger.info("COMMAND confirmation_requested action=%s target=%s", command.action, command.target)
            return self._finish(prompt)
        return self._execute(command)

    def _process_confirmation(self, text: str, command: Command) -> ProcessResult:
        answer = self._confirmations.resolve(text)
        if answer is ConfirmationAnswer.UNKNOWN:
            return ProcessResult("Responde sí para confirmar o no para cancelar la acción pendiente.")
        self._confirmations.clear()
        if answer is ConfirmationAnswer.NO:
            self._logger.info("COMMAND cancelled action=%s target=%s", command.action, command.target)
            return ProcessResult("Acción cancelada.")
        if command.action == "memory_clear_all" and command.arguments.get("double_confirmation") is not True:
            second = Command(command.action, command.target, {**command.arguments, "double_confirmation": True})
            prompt = "Esta acción eliminará todos los recuerdos persistentes. Responde sí una segunda vez para confirmarla definitivamente."
            self._confirmations.request(second, prompt)
            return ProcessResult(prompt)
        return self._execute(command)

    def _execute(self, command: Command) -> ProcessResult:
        input_actions = {
            "move_mouse",
            "move_mouse_center",
            "mouse_click",
            "mouse_double_click",
            "mouse_right_click",
            "scroll",
            "type_text",
            "press_key",
            "hotkey",
            "automation_sequence",
            "browser_sequence",
            "browser_click",
            "browser_fill",
            "browser_select",
            "browser_submit",
            "terminal_execute",
            "terminal_sequence",
            "terminal_stop_process",
        }
        was_observing = self._permissions.mode is OperationMode.OBSERVE
        if command.action in input_actions:
            self._permissions.enter_execute_mode()
            self._logger.info("MODE execute action=%s", command.action)
        if command.action == "type_text":
            self._logger.info("ACTION type=type_text length=%s", len(str(command.arguments.get("text", ""))))
        elif command.action == "browser_fill":
            self._logger.info("ACTION type=browser_fill field=%s length=%s", command.arguments.get("field", ""), len(str(command.arguments.get("text", ""))))
        elif command.action == "browser_select":
            self._logger.info("ACTION type=browser_select length=%s", len(str(command.arguments.get("text", ""))))
        elif command.action == "terminal_execute":
            terminal = command.arguments.get("terminal_command")
            self._logger.info("TERMINAL action=execute executable=%s risk=%s", getattr(terminal, "executable", ""), getattr(getattr(terminal, "risk_level", None), "name", ""))
        elif command.action == "reminder_create":
            self._logger.info("ACTION type=reminder_create")
        elif command.action == "memory_remember":
            self._logger.info("ACTION type=memory_remember")
        else:
            self._logger.info("ACTION type=%s target=%s", command.action, command.target)
        try:
            result = self._router.execute(command)
            self._logger.info("RESULT action=%s success=%s", command.action, result.success)
            return self._finish(result.message, error=not result.success)
        finally:
            if command.action in input_actions and was_observing:
                self._permissions.enter_observe_mode()
                self._logger.info("MODE observe")

    @staticmethod
    def _confirmation_prompt(command: Command) -> str:
        if command.action == "close_application":
            return f"¿Confirmas que quieres cerrar {command.target or 'esa aplicación'}?"
        if command.action == "open_application":
            return "¿Confirmas que quieres abrir la Terminal o consola de comandos?"
        if command.action == "type_text":
            if command.arguments.get("sensitive") is True:
                return "La ventana activa parece sensible. ¿Confirmas adicionalmente que quieres escribir allí?"
            title = command.arguments.get("window_title")
            return f"¿Confirmas que quieres escribir en {title}?" if isinstance(title, str) and title else "¿Confirmas que quieres escribir texto en la ventana activa?"
        if command.action in {"mouse_click", "mouse_double_click", "mouse_right_click"}:
            if "x" not in command.arguments or "y" not in command.arguments:
                return "¿Confirmas el click en la posición actual del mouse?"
            return "¿Confirmas el click en la posición indicada?"
        if command.action == "hotkey":
            return "¿Confirmas que quieres usar ese atajo de teclado?"
        if command.action == "automation_sequence":
            return "¿Confirmas que quieres ejecutar esta automatización segura?"
        if command.action == "orchestrator_goal":
            return "Prepararé y ejecutaré un plan multiagente validado. Las acciones que cambien el equipo requerirán esta confirmación. ¿Confirmas?"
        if command.action == "automation_create_engine":
            return "Crearé esta automatización persistente con acciones registradas. ¿Confirmas?"
        if command.action == "automation_run_engine":
            return "¿Confirmas que quieres ejecutar esta automatización manual?"
        if command.action == "automation_enable_engine":
            return "¿Confirmas que quieres activar esta automatización?"
        if command.action == "automation_disable_engine":
            return "¿Confirmas que quieres desactivar esta automatización?"
        if command.action == "memory_forget":
            return "¿Confirmas que quieres eliminar ese recuerdo persistente?"
        if command.action == "memory_update":
            return "¿Confirmas que quieres actualizar ese recuerdo persistente?"
        if command.action == "memory_export":
            return "¿Confirmas que quieres exportar tus recuerdos locales a un archivo?"
        if command.action == "memory_clear_all":
            return "¿Confirmas que quieres borrar todos los recuerdos persistentes?"
        if command.action == "code_apply_patch":
            return "¿Confirmas que quieres aplicar el parche de código mostrado?"
        if command.action == "code_project_apply":
            return "¿Confirmas que quieres crear el proyecto y sus archivos desde el borrador mostrado?"
        if command.action in {"code_create_file", "code_rename_file", "code_delete_file"}:
            return "¿Confirmas que quieres aplicar este cambio de archivos del proyecto?"
        if command.action == "code_commit":
            return "¿Confirmas que quieres crear un commit selectivo solo con los archivos modificados por JARVIS?"
        if command.action == "code_run_tests":
            return "¿Confirmas que quieres ejecutar los tests detectados mediante Terminal Agent?"
        if command.action == "code_run_lint":
            return "¿Confirmas que quieres ejecutar lint mediante Terminal Agent?"
        if command.action == "code_run_build":
            return "¿Confirmas que quieres ejecutar el build mediante Terminal Agent?"
        if command.action == "code_open_vscode":
            return "¿Confirmas que quieres abrir este contexto en VS Code?"
        if command.action == "iot_register_device":
            return "¿Confirmas que quieres registrar y autorizar ese ESP32?"
        if command.action == "iot_create_rule":
            return "Crearé esta automatización IoT persistente. ¿Confirmas?"
        if command.action == "iot_set_relay":
            return "¿Confirmas que quieres cambiar el relay del dispositivo registrado?"
        if command.action == "iot_set_servo":
            return "¿Confirmas que quieres mover el servo del dispositivo registrado?"
        if command.action == "iot_set_buzzer":
            return "¿Confirmas que quieres activar o desactivar el buzzer del dispositivo registrado?"
        if command.action == "memory_backup":
            return "¿Confirmas que quieres crear una copia de seguridad local de tu memoria?"
        if command.action == "reminder_cancel":
            return "¿Confirmas que quieres cancelar ese recordatorio?"
        if command.action == "routine_save":
            return "¿Confirmas que quieres guardar esta rutina segura?"
        if command.action == "routine_execute":
            return "¿Confirmas que quieres ejecutar esta rutina?"
        if command.action == "browser_stop":
            return "¿Confirmas que quieres cerrar el navegador de JARVIS?"
        if command.action == "browser_close_tab":
            return "¿Confirmas que quieres cerrar esta pestaña?"
        if command.action == "browser_fill":
            return "¿Confirmas que quieres rellenar ese campo de la página?"
        if command.action == "browser_select":
            return "¿Confirmas que quieres seleccionar esa opción de la página?"
        if command.action in {"browser_click", "browser_submit"}:
            return "¿Confirmas que quieres activar ese elemento de la página?"
        if command.action == "browser_sequence":
            return "¿Confirmas que quieres ejecutar esta secuencia segura de navegación?"
        if command.action == "terminal_execute":
            from app.terminal.security import display_command

            terminal = command.arguments.get("terminal_command")
            if terminal is not None:
                return f"JARVIS ejecutará:\n{display_command(terminal)}\n\nDirectorio:\n{getattr(terminal, 'cwd', '')}\n\nRiesgo:\n{getattr(getattr(terminal, 'risk_level', None), 'name', '')}\n\n¿Confirmas?"
            return "¿Confirmas que quieres ejecutar ese comando de terminal?"
        if command.action == "terminal_sequence":
            return "¿Confirmas que quieres ejecutar esta secuencia de terminal validada?"
        if command.action == "terminal_stop_process":
            return "¿Confirmas que quieres detener ese proceso administrado por JARVIS?"
        if command.action == "terminal_open_here":
            return "¿Confirmas que quieres abrir PowerShell en el directorio actual?"
        if command.action == "terminal_set_mode" and command.target == "execute":
            return "¿Confirmas que quieres activar el modo de ejecución controlada? Las operaciones modificadoras seguirán requiriendo validación."
        if command.arguments.get("mute") is True:
            return "¿Confirmas que quieres silenciar el computador?"
        return "¿Confirmas que quieres poner el volumen al 0 %?"
