from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.input.mouse import MouseController
from app.system.window_manager import WindowManager
from app.vision.analyzer import ContextVisionProvider, VisionProvider
from app.vision.context import ScreenContext
from app.vision.screenshot import ScreenshotService


@dataclass(slots=True)
class VisionService:
    screenshots: ScreenshotService
    windows: WindowManager
    mouse: MouseController
    provider: VisionProvider
    latest_context: ScreenContext | None = field(default=None, init=False)

    @classmethod
    def create_default(cls, windows: WindowManager, mouse: MouseController) -> "VisionService":
        return cls(ScreenshotService(windows), windows, mouse, ContextVisionProvider())

    def context(self, image: object | None = None) -> ScreenContext:
        active = self.windows.get_active_window()
        width, height = self.mouse.screen_size()
        context = ScreenContext(
            active_window=active.title if active else None,
            active_process=active.process_name if active else None,
            cursor_position=self.mouse.get_position(),
            screen_width=width,
            screen_height=height,
            captured_at=datetime.now(timezone.utc),
            latest_capture=image,
        )
        self.latest_context = context
        return context

    def capture_screen(self) -> str:
        image = self.screenshots.capture_screen()
        self.context(image)
        return f"Captura de pantalla realizada: {image.width} por {image.height} píxeles."

    def capture_active_window(self) -> str:
        image = self.screenshots.capture_active_window()
        self.context(image)
        return f"Captura de la ventana activa realizada: {image.width} por {image.height} píxeles."

    def analyze_screen(self, question: str, active_window: bool = False) -> str:
        image = self.screenshots.capture_active_window() if active_window else self.screenshots.capture_screen()
        context = self.context(image)
        return self.provider.analyze_image(image, question, context)
