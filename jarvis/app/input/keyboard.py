from __future__ import annotations

from dataclasses import dataclass

from app.commands.base import CommandResult


ALLOWED_KEYS: frozenset[str] = frozenset({"enter", "escape", "tab", "backspace", "space", "up", "down", "left", "right"})
ALLOWED_HOTKEYS: dict[str, tuple[str, str]] = {
    "copy": ("ctrl", "c"),
    "paste": ("ctrl", "v"),
    "select_all": ("ctrl", "a"),
    "save": ("ctrl", "s"),
    "undo": ("ctrl", "z"),
    "redo": ("ctrl", "y"),
    "find": ("ctrl", "f"),
}
SENSITIVE_WINDOW_MARKERS: frozenset[str] = frozenset({"password", "contraseña", "contrasena", "bank", "banco", "payment", "pago", "wallet"})


def is_sensitive_window(title: str | None) -> bool:
    normalized = (title or "").casefold()
    return any(marker in normalized for marker in SENSITIVE_WINDOW_MARKERS)


@dataclass(slots=True)
class KeyboardController:
    backend: object | None = None

    def __post_init__(self) -> None:
        if self.backend is None:
            import pyautogui

            pyautogui.FAILSAFE = True
            pyautogui.PAUSE = 0.1
            self.backend = pyautogui

    def type_text(self, text: str) -> CommandResult:
        if not text:
            return CommandResult(False, "Indica el texto que quieres escribir.")
        if len(text) > 2000:
            return CommandResult(False, "El texto supera el límite seguro de 2000 caracteres.")
        try:
            self.backend.write(text, interval=0.01)
            return CommandResult(True, f"Escribí {len(text)} caracteres.")
        except Exception:
            return CommandResult(False, "No pude escribir el texto. El fail-safe puede estar activo.")

    def press_key(self, key: str) -> CommandResult:
        if key not in ALLOWED_KEYS:
            return CommandResult(False, "Esa tecla no está permitida.")
        try:
            self.backend.press(key)
            return CommandResult(True, f"Presioné {key}.")
        except Exception:
            return CommandResult(False, "No pude presionar esa tecla. El fail-safe puede estar activo.")

    def hotkey(self, name: str) -> CommandResult:
        combination = ALLOWED_HOTKEYS.get(name)
        if combination is None:
            return CommandResult(False, "Ese atajo no está permitido.")
        try:
            self.backend.hotkey(*combination)
            return CommandResult(True, f"Atajo {name} ejecutado.")
        except Exception:
            return CommandResult(False, "No pude ejecutar ese atajo. El fail-safe puede estar activo.")
