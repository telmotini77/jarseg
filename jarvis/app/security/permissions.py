from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from app.commands.base import ALLOWED_COMMANDS, Command
from app.commands.classifier import normalize_text


class SecurityLevel(Enum):
    SAFE = 1
    CONFIRMATION = 2
    SENSITIVE = 3
    RESTRICTED = 4
    BLOCKED = 5


class OperationMode(str, Enum):
    """JARVIS observes by default and enters execution only for a clear action."""

    OBSERVE = "observe"
    EXECUTE = "execute"


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    level: SecurityLevel
    message: str | None = None


class PermissionManager:
    def __init__(self) -> None:
        self._mode = OperationMode.OBSERVE

    @property
    def mode(self) -> OperationMode:
        return self._mode

    def enter_execute_mode(self) -> None:
        self._mode = OperationMode.EXECUTE

    def enter_observe_mode(self) -> None:
        self._mode = OperationMode.OBSERVE

    def evaluate(self, command: Command) -> PermissionDecision:
        if command.action not in ALLOWED_COMMANDS:
            return PermissionDecision(SecurityLevel.RESTRICTED, "Esa acción todavía no está permitida.")
        if command.action == "type_text" and any(
            marker in str(command.arguments.get("text", "")).casefold()
            for marker in {"password", "contraseña", "contrasena"}
        ):
            return PermissionDecision(SecurityLevel.RESTRICTED, "JARVIS no escribe contraseñas automáticamente.")
        if command.action == "automation_sequence":
            return PermissionDecision(SecurityLevel.SENSITIVE)
        if command.action in {"orchestrator_goal", "automation_create_engine", "automation_run_engine"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action in {"automation_enable_engine", "automation_disable_engine"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "terminal_execute":
            terminal = command.arguments.get("terminal_command")
            level = getattr(terminal, "risk_level", SecurityLevel.RESTRICTED)
            if level is SecurityLevel.BLOCKED:
                return PermissionDecision(SecurityLevel.BLOCKED, "Esa operación está bloqueada por la política de seguridad de Terminal Agent.")
            if level is SecurityLevel.RESTRICTED:
                return PermissionDecision(SecurityLevel.RESTRICTED, "Ese comando no está permitido por Terminal Agent.")
            if level in {SecurityLevel.CONFIRMATION, SecurityLevel.SENSITIVE}:
                return PermissionDecision(level)
            return PermissionDecision(SecurityLevel.SAFE)
        if command.action == "terminal_sequence":
            return PermissionDecision(SecurityLevel.SENSITIVE)
        if command.action in {"terminal_stop_process", "terminal_open_here"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "terminal_set_mode" and command.target == "execute":
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "browser_sequence":
            return PermissionDecision(SecurityLevel.SENSITIVE)
        if command.action == "browser_fill_email":
            return PermissionDecision(SecurityLevel.SENSITIVE, "El correo se completará solo en un campo HTTPS verificado.")
        if command.action == "browser_trusted_login":
            return PermissionDecision(SecurityLevel.CONFIRMATION, "Se abrirá Google en tu perfil normal de Chrome.")
        if command.action in {"browser_fill", "browser_select", "browser_click", "browser_submit", "browser_close_tab", "browser_stop"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action in {"memory_forget", "memory_update", "memory_backup", "memory_export", "reminder_cancel", "routine_save", "routine_execute"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "memory_clear_all":
            return PermissionDecision(SecurityLevel.SENSITIVE)
        if command.action in {"code_apply_patch", "code_project_apply", "code_create_file", "code_rename_file", "code_delete_file", "code_commit"}:
            return PermissionDecision(SecurityLevel.SENSITIVE)
        if command.action in {"code_run_tests", "code_run_lint", "code_run_build", "code_open_vscode"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action in {"iot_register_device", "iot_create_rule", "iot_set_relay", "iot_set_servo", "iot_set_buzzer"}:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "cyberseg_start_capture":
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "hotkey" and command.arguments.get("name") == "paste":
            return PermissionDecision(SecurityLevel.SENSITIVE)
        if command.action in {"type_text", "mouse_click", "mouse_double_click", "mouse_right_click", "hotkey"}:
            if command.action.startswith("mouse_") and not {
                "x",
                "y",
            }.issubset(command.arguments):
                return PermissionDecision(SecurityLevel.SENSITIVE)
            if command.arguments.get("sensitive") is True:
                return PermissionDecision(SecurityLevel.SENSITIVE)
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "close_application":
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "open_application" and normalize_text(command.target or "") in {
            "terminal", "windows terminal", "powershell", "power shell", "cmd", "simbolo del sistema", "command prompt",
        }:
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        if command.action == "set_volume" and (
            command.arguments.get("level") == 0 or command.arguments.get("mute") is True
        ):
            return PermissionDecision(SecurityLevel.CONFIRMATION)
        return PermissionDecision(SecurityLevel.SAFE)
