from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from PIL import Image


class WindowBoundsProvider(Protocol):
    def active_bounds(self) -> tuple[int, int, int, int] | None: ...


class ScreenshotError(RuntimeError):
    """The screen could not be captured."""


@dataclass(slots=True)
class ScreenshotService:
    """Captures pixels in memory only; no image is written or logged."""

    window_manager: WindowBoundsProvider | None = None

    def capture_screen(self) -> Image.Image:
        try:
            import mss

            with mss.mss() as capture:
                monitor = capture.monitors[1]
                frame = capture.grab(monitor)
                return Image.frombytes("RGB", frame.size, frame.rgb)
        except Exception as error:
            raise ScreenshotError("No pude capturar la pantalla actual.") from error

    def capture_region(self, left: int, top: int, width: int, height: int) -> Image.Image:
        if left < 0 or top < 0 or width <= 0 or height <= 0:
            raise ScreenshotError("La región de captura no es válida.")
        try:
            import mss

            with mss.mss() as capture:
                frame = capture.grab({"left": left, "top": top, "width": width, "height": height})
                return Image.frombytes("RGB", frame.size, frame.rgb)
        except Exception as error:
            raise ScreenshotError("No pude capturar esa región de pantalla.") from error

    def capture_active_window(self) -> Image.Image:
        if self.window_manager is None:
            raise ScreenshotError("El gestor de ventanas no está disponible.")
        bounds = self.window_manager.active_bounds()
        if bounds is None:
            raise ScreenshotError("No encontré una ventana activa para capturar.")
        left, top, width, height = bounds
        return self.capture_region(left, top, width, height)
