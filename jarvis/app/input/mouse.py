from __future__ import annotations

from dataclasses import dataclass

from app.commands.base import CommandResult


class MouseValidationError(ValueError):
    """The requested coordinate is outside the current desktop."""


def validate_coordinates(x: int, y: int, width: int, height: int) -> tuple[int, int]:
    if not 0 <= x < width or not 0 <= y < height:
        raise MouseValidationError("La posición solicitada está fuera de los límites de la pantalla.")
    return x, y


@dataclass(slots=True)
class MouseController:
    backend: object | None = None

    def __post_init__(self) -> None:
        if self.backend is None:
            import pyautogui

            pyautogui.FAILSAFE = True
            pyautogui.PAUSE = 0.1
            self.backend = pyautogui

    def screen_size(self) -> tuple[int, int]:
        size = self.backend.size()
        return int(size.width), int(size.height)

    def get_position(self) -> tuple[int, int]:
        point = self.backend.position()
        return int(point.x), int(point.y)

    def move_to(self, x: int, y: int) -> CommandResult:
        try:
            validate_coordinates(x, y, *self.screen_size())
            self.backend.moveTo(x, y)
            return CommandResult(True, f"Moví el mouse a {x}, {y}.")
        except MouseValidationError as error:
            return CommandResult(False, str(error))
        except Exception:
            return CommandResult(False, "No pude mover el mouse. El fail-safe puede estar activo.")

    def move_to_center(self) -> CommandResult:
        width, height = self.screen_size()
        return self.move_to(width // 2, height // 2)

    def click(self, x: int | None = None, y: int | None = None, button: str = "left", clicks: int = 1) -> CommandResult:
        try:
            if x is None or y is None:
                x, y = self.get_position()
            validate_coordinates(x, y, *self.screen_size())
            self.backend.click(x=x, y=y, clicks=clicks, button=button)
            labels = {"left": "Click", "right": "Click derecho"}
            prefix = "Doble click" if clicks == 2 else labels.get(button, "Click")
            return CommandResult(True, f"{prefix} realizado en {x}, {y}.")
        except MouseValidationError as error:
            return CommandResult(False, str(error))
        except Exception:
            return CommandResult(False, "No pude realizar el click. El fail-safe puede estar activo.")

    def double_click(self, x: int | None = None, y: int | None = None) -> CommandResult:
        return self.click(x, y, clicks=2)

    def right_click(self, x: int | None = None, y: int | None = None) -> CommandResult:
        return self.click(x, y, button="right")

    def scroll(self, amount: int) -> CommandResult:
        if amount == 0:
            return CommandResult(False, "Indica una dirección para el desplazamiento.")
        try:
            self.backend.scroll(amount)
            return CommandResult(True, "Desplacé la página hacia arriba." if amount > 0 else "Desplacé la página hacia abajo.")
        except Exception:
            return CommandResult(False, "No pude desplazar la página. El fail-safe puede estar activo.")
