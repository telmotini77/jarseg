import pytest

from app.commands.base import CommandName, RouteType
from app.commands.router import CommandRouter


@pytest.mark.parametrize("text", ["Jarvis salir", "jarvis, cerrar"])
def test_router_detects_exit_commands(text: str) -> None:
    route = CommandRouter().route(text)
    assert route.type is RouteType.COMMAND
    assert route.command is CommandName.EXIT


@pytest.mark.parametrize("text", ["detener", "Jarvis cancela", "Jarvis para"])
def test_router_detects_emergency_cancel_commands(text: str) -> None:
    route = CommandRouter().route(text)
    assert route.type is RouteType.COMMAND
    assert route.command is CommandName.CANCEL


def test_router_keeps_regular_text_as_conversation() -> None:
    route = CommandRouter().route("Jarvis, explícame Docker")
    assert route.type is RouteType.CONVERSATION
    assert route.command is None
