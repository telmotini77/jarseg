from __future__ import annotations

import logging
from types import SimpleNamespace

from app.ai.provider import AIProvider
from app.commands.base import Command, CommandResult
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis
from app.security.confirmation import ConfirmationAnswer, ConfirmationManager
from app.security.permissions import OperationMode, PermissionManager, SecurityLevel


class FakeProvider(AIProvider):
    def generate_response(self, history: list[dict[str, str]]) -> str:
        return "respuesta"


class FakeApps:
    def open(self, target: str | None) -> CommandResult:
        return CommandResult(True, "abierto")

    def close(self, target: str | None) -> CommandResult:
        return CommandResult(True, "cerrado")


class FakeKeyboard:
    def type_text(self, text: str) -> CommandResult:
        return CommandResult(True, f"Escribí {len(text)} caracteres.")

    def press_key(self, key: str) -> CommandResult:
        return CommandResult(True, key)

    def hotkey(self, name: str) -> CommandResult:
        return CommandResult(True, name)


class FakeWindows:
    def get_active_window(self) -> SimpleNamespace:
        return SimpleNamespace(title="Bloc de notas")


def test_permission_levels() -> None:
    manager = PermissionManager()
    assert manager.mode is OperationMode.OBSERVE
    assert manager.evaluate(Command("open_application", target="vscode")).level is SecurityLevel.SAFE
    assert manager.evaluate(Command("close_application", target="spotify")).level is SecurityLevel.CONFIRMATION
    assert manager.evaluate(Command("hotkey", arguments={"name": "paste"})).level is SecurityLevel.SENSITIVE
    assert manager.evaluate(Command("type_text", arguments={"text": "mi password"})).level is SecurityLevel.RESTRICTED
    assert manager.evaluate(Command("browser_fill_email")).level is SecurityLevel.SENSITIVE
    assert manager.evaluate(Command("browser_trusted_login")).level is SecurityLevel.CONFIRMATION
    assert manager.evaluate(Command("delete_file")).level is SecurityLevel.RESTRICTED
    manager.enter_execute_mode()
    assert manager.mode is OperationMode.EXECUTE
    manager.enter_observe_mode()
    assert manager.mode is OperationMode.OBSERVE


def test_confirmation_manager_understands_yes_no() -> None:
    manager = ConfirmationManager()
    assert manager.resolve("Sí") is ConfirmationAnswer.YES
    assert manager.resolve("no") is ConfirmationAnswer.NO
    assert manager.resolve("tal vez") is ConfirmationAnswer.UNKNOWN


def test_jarvis_requires_confirmation_before_closing() -> None:
    router = CommandRouter(applications=FakeApps())
    jarvis = Jarvis(FakeProvider(), ConversationManager(), router, logging.getLogger("test"))
    requested = jarvis.process("Jarvis cierra Spotify")
    assert "Confirmas" in requested.response
    cancelled = jarvis.process("No")
    assert cancelled.response == "Acción cancelada."


def test_jarvis_executes_after_confirmation() -> None:
    router = CommandRouter(applications=FakeApps())
    jarvis = Jarvis(FakeProvider(), ConversationManager(), router, logging.getLogger("test"))
    jarvis.process("Jarvis cierra Spotify")
    confirmed = jarvis.process("Sí")
    assert confirmed.response == "cerrado"


def test_emergency_cancel_has_priority_over_a_pending_confirmation() -> None:
    router = CommandRouter(applications=FakeApps())
    jarvis = Jarvis(FakeProvider(), ConversationManager(), router, logging.getLogger("test"))
    jarvis.process("Jarvis cierra Spotify")
    cancelled = jarvis.process("Jarvis cancela")
    assert "pendientes canceladas" in cancelled.response


def test_execute_mode_is_temporary_for_confirmed_text_input() -> None:
    permissions = PermissionManager()
    router = CommandRouter(keyboard=FakeKeyboard(), windows=FakeWindows())
    jarvis = Jarvis(FakeProvider(), ConversationManager(), router, logging.getLogger("test"), permissions=permissions)
    requested = jarvis.process("Jarvis escribe prueba")
    assert "Confirmas" in requested.response
    completed = jarvis.process("Sí")
    assert completed.response == "Escribí 6 caracteres."
    assert permissions.mode is OperationMode.OBSERVE
