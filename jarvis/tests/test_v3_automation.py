from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace

from PIL import Image

from app.automation.action import Action
from app.automation.action_queue import ActionQueue
from app.automation.registry import ACTION_REGISTRY, is_registered_action
from app.commands.apps import ApplicationService
from app.commands.base import Command, CommandResult
from app.commands.router import CommandRouter
from app.input.keyboard import ALLOWED_HOTKEYS, ALLOWED_KEYS, KeyboardController, is_sensitive_window
from app.input.mouse import MouseController, validate_coordinates
from app.security.permissions import SecurityLevel
from app.system.window_manager import WindowInfo, WindowManager
from app.vision.analyzer import ContextVisionProvider
from app.vision.context import ScreenContext
from app.vision.screenshot import ScreenshotError, ScreenshotService
from app.vision.service import VisionService


class FakeMouseBackend:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []

    def size(self):
        return SimpleNamespace(width=800, height=600)

    def position(self):
        return SimpleNamespace(x=25, y=30)

    def moveTo(self, x: int, y: int) -> None:
        self.events.append(("move", x, y))

    def click(self, **kwargs: object) -> None:
        self.events.append(("click", kwargs))

    def scroll(self, amount: int) -> None:
        self.events.append(("scroll", amount))


class FakeKeyboardBackend:
    def __init__(self) -> None:
        self.events: list[tuple[object, ...]] = []

    def write(self, text: str, interval: float) -> None:
        self.events.append(("write", text, interval))

    def press(self, key: str) -> None:
        self.events.append(("press", key))

    def hotkey(self, *keys: str) -> None:
        self.events.append(("hotkey", *keys))


@dataclass
class FakeApps:
    events: list[str]

    def open(self, target: str | None) -> CommandResult:
        self.events.append("open_application")
        return CommandResult(True, f"Abriendo {target}.")

    def close(self, target: str | None) -> CommandResult:
        return CommandResult(True, "cerrada")


@dataclass
class FakeWindows:
    events: list[str]
    title: str = "Bloc de notas"

    def get_active_window(self) -> WindowInfo:
        return WindowInfo(1, self.title, "notepad.exe", 0, 0, 300, 200)

    def wait_for_window(self, target: str | None) -> WindowInfo:
        self.events.append("wait_for_window")
        return self.get_active_window()

    def focus_window(self, target: str | None) -> CommandResult:
        self.events.append("focus_window")
        return CommandResult(True, "Ventana enfocada.")

    def focus_previous_window(self) -> CommandResult:
        return CommandResult(True, "Ventana anterior enfocada.")

    def list_open_windows(self) -> CommandResult:
        return CommandResult(True, "Ventanas abiertas: 1. Bloc de notas")

    def active_window(self) -> CommandResult:
        return CommandResult(True, "La ventana activa es Bloc de notas.")

    def minimize_window(self, target: str | None) -> CommandResult:
        return CommandResult(True, "minimizada")

    def maximize_window(self, target: str | None) -> CommandResult:
        return CommandResult(True, "maximizada")

    def restore_window(self, target: str | None) -> CommandResult:
        return CommandResult(True, "restaurada")


@dataclass
class FakeKeyboard:
    events: list[str]

    def type_text(self, text: str) -> CommandResult:
        self.events.append("type_text")
        return CommandResult(True, f"Escribí {len(text)} caracteres.")

    def press_key(self, key: str) -> CommandResult:
        return CommandResult(True, key)

    def hotkey(self, name: str) -> CommandResult:
        return CommandResult(True, name)


def test_coordinate_validation_and_mouse_controller_are_safe_with_fake_backend() -> None:
    assert validate_coordinates(799, 599, 800, 600) == (799, 599)
    mouse = MouseController(backend=FakeMouseBackend())
    assert mouse.move_to(100, 120).success
    assert not mouse.move_to(800, 120).success
    assert mouse.click(50, 50).success
    assert mouse.double_click(60, 60).success
    assert mouse.right_click(70, 70).success
    assert mouse.scroll(-5).success
    assert mouse.backend.events == [
        ("move", 100, 120),
        ("click", {"x": 50, "y": 50, "clicks": 1, "button": "left"}),
        ("click", {"x": 60, "y": 60, "clicks": 2, "button": "left"}),
        ("click", {"x": 70, "y": 70, "clicks": 1, "button": "right"}),
        ("scroll", -5),
    ]


def test_keyboard_only_accepts_allow_list_with_fake_backend() -> None:
    keyboard = KeyboardController(backend=FakeKeyboardBackend())
    assert keyboard.press_key("enter").success
    assert not keyboard.press_key("delete").success
    assert keyboard.hotkey("copy").success
    assert not keyboard.hotkey("close_window").success
    assert keyboard.backend.events == [("press", "enter"), ("hotkey", *ALLOWED_HOTKEYS["copy"])]
    assert "enter" in ALLOWED_KEYS


def test_sensitive_window_detection() -> None:
    assert is_sensitive_window("Banco - iniciar sesión")
    assert is_sensitive_window("Password manager")
    assert not is_sensitive_window("Bloc de notas")


def test_action_registry_and_queue_reject_unregistered_actions() -> None:
    queue = ActionQueue()
    action = Action("move_mouse", parameters={"x": 10, "y": 10})
    queue.enqueue(action)
    assert queue.pop_next() == action
    queue.enqueue(action)
    queue.cancel()
    assert queue.cancelled
    assert queue.pop_next() is None
    assert is_registered_action("type_text")
    assert "capture_screen" in ACTION_REGISTRY
    assert not is_registered_action("run_powershell")


def test_screen_context_keeps_capture_ephemeral_and_hidden_from_repr() -> None:
    context = ScreenContext("Bloc de notas", "notepad.exe", (1, 2), 1920, 1080, datetime.now(), object())
    assert context.active_window == "Bloc de notas"
    assert "latest_capture" not in repr(context)


def test_window_manager_finds_a_window_from_mocked_native_inventory() -> None:
    manager = WindowManager()
    windows = [
        WindowInfo(1, "Google Chrome", "chrome.exe", 0, 0, 100, 100),
        WindowInfo(2, "Bloc de notas", "notepad.exe", 0, 0, 100, 100),
    ]
    manager.list_windows = lambda limit=20: windows[:limit]  # type: ignore[method-assign]
    assert manager.find_window("chrome") == windows[0]
    assert manager.find_window("notepad.exe") == windows[1]


def test_screenshot_rejects_invalid_regions_without_capturing_real_screen() -> None:
    service = ScreenshotService()
    try:
        service.capture_region(-1, 0, 20, 20)
    except ScreenshotError as error:
        assert "no es válida" in str(error)
    else:
        raise AssertionError("La región fuera de pantalla debía rechazarse.")


class FakeScreenshots:
    def capture_screen(self) -> Image.Image:
        return Image.new("RGB", (320, 200))

    def capture_active_window(self) -> Image.Image:
        return Image.new("RGB", (120, 100))


def test_vision_context_and_local_provider_do_not_need_a_real_capture() -> None:
    events: list[str] = []
    windows = FakeWindows(events)
    mouse = MouseController(backend=FakeMouseBackend())
    vision = VisionService(FakeScreenshots(), windows, mouse, ContextVisionProvider())  # type: ignore[arg-type]
    response = vision.analyze_screen("¿Qué tengo abierto?")
    assert vision.latest_context is not None
    assert vision.latest_context.active_window == "Bloc de notas"
    assert "no se ha enviado fuera" in response


def test_router_parses_v3_commands_without_running_real_input() -> None:
    router = CommandRouter()
    assert router.parse("Jarvis mira mi pantalla").action == "analyze_screen"
    assert router.parse("Jarvis captura la pantalla").action == "capture_screen"
    assert router.parse("Jarvis captura esta ventana").action == "capture_active_window"
    assert router.parse("Jarvis mira mi error y dime qué hago").action == "analyze_screen"
    assert router.parse("Jarvis dime que ventanas tengo abiertas").action == "list_windows"
    assert router.parse("Jarvis cambia a Chrome").action == "focus_window"
    assert router.parse("Jarvis vuelve a la ventana anterior").action == "focus_previous_window"
    assert router.parse("Jarvis mueve el mouse al centro").action == "move_mouse_center"
    click = router.parse("Jarvis haz click en 500, 400")
    assert click == Command("mouse_click", arguments={"x": 500, "y": 400})
    assert router.parse("Jarvis escribe hola mundo").action == "type_text"
    preserved = router.parse('Jarvis escribe "Hola, JARVIS está listo"')
    assert preserved.arguments["text"] == "Hola, JARVIS está listo"
    assert router.parse("Jarvis presiona Enter").action == "press_key"


def test_simulated_open_notepad_and_type_sequence_uses_registered_steps() -> None:
    events: list[str] = []
    router = CommandRouter(
        applications=FakeApps(events),
        windows=FakeWindows(events),
        keyboard=FakeKeyboard(events),
        mouse=MouseController(backend=FakeMouseBackend()),
    )
    command = router.parse("Jarvis abre el bloc de notas y escribe hola")
    assert command is not None and command.action == "automation_sequence"
    result = router.execute(command)
    assert result.success
    assert events == ["open_application", "wait_for_window", "focus_window", "type_text"]
    assert SecurityLevel.SENSITIVE.value == 3
