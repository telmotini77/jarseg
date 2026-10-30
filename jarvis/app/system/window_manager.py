from __future__ import annotations

import time
from dataclasses import dataclass

import psutil

from app.commands.base import CommandResult


class WindowManagerError(RuntimeError):
    """Windows API operations are not available."""


@dataclass(frozen=True, slots=True)
class WindowInfo:
    handle: int
    title: str
    process_name: str | None
    left: int
    top: int
    width: int
    height: int


class WindowManager:
    """Small Windows-native window manager with title-based allow-list style matching."""

    def __init__(self) -> None:
        self._active_handle: int | None = None
        self._previous_handle: int | None = None

    def _modules(self):
        try:
            import win32con
            import win32gui
            import win32process

            return win32con, win32gui, win32process
        except ImportError as error:
            raise WindowManagerError("El gestor de ventanas requiere pywin32 en Windows.") from error

    @staticmethod
    def _process_name(process_id: int) -> str | None:
        try:
            return psutil.Process(process_id).name()
        except (psutil.Error, OSError):
            return None

    def _info(self, handle: int) -> WindowInfo | None:
        _con, gui, process = self._modules()
        title = gui.GetWindowText(handle).strip()
        if not title:
            return None
        left, top, right, bottom = gui.GetWindowRect(handle)
        _thread_id, process_id = process.GetWindowThreadProcessId(handle)
        return WindowInfo(
            handle=handle,
            title=title,
            process_name=self._process_name(process_id),
            left=left,
            top=top,
            width=max(0, right - left),
            height=max(0, bottom - top),
        )

    def list_windows(self, limit: int = 20) -> list[WindowInfo]:
        _con, gui, _process = self._modules()
        handles: list[int] = []

        def collect(handle: int, _extra: object) -> None:
            if gui.IsWindowVisible(handle) and gui.GetWindowText(handle).strip():
                handles.append(handle)

        gui.EnumWindows(collect, None)
        windows = [item for handle in handles if (item := self._info(handle)) is not None]
        return windows[:limit]

    def get_active_window(self) -> WindowInfo | None:
        _con, gui, _process = self._modules()
        handle = gui.GetForegroundWindow()
        window = self._info(handle) if handle else None
        if window is not None and window.handle != self._active_handle:
            self._previous_handle = self._active_handle
            self._active_handle = window.handle
        return window

    def active_bounds(self) -> tuple[int, int, int, int] | None:
        active = self.get_active_window()
        if active is None or active.width <= 0 or active.height <= 0:
            return None
        return active.left, active.top, active.width, active.height

    def find_window(self, target: str | None) -> WindowInfo | None:
        if not target:
            return None
        needle = target.casefold().strip()
        for window in self.list_windows():
            if needle in window.title.casefold() or (window.process_name and needle in window.process_name.casefold()):
                return window
        return None

    def list_open_windows(self) -> CommandResult:
        try:
            windows = self.list_windows()
        except WindowManagerError as error:
            return CommandResult(False, str(error))
        if not windows:
            return CommandResult(True, "No encontré ventanas abiertas visibles.")
        names = "; ".join(f"{index}. {window.title}" for index, window in enumerate(windows, 1))
        return CommandResult(True, f"Ventanas abiertas: {names}")

    def active_window(self) -> CommandResult:
        try:
            window = self.get_active_window()
        except WindowManagerError as error:
            return CommandResult(False, str(error))
        if window is None:
            return CommandResult(False, "No encontré una ventana activa.")
        return CommandResult(True, f"La ventana activa es {window.title}.")

    def focus_window(self, target: str | None) -> CommandResult:
        try:
            self.get_active_window()
            window = self.find_window(target)
            if window is None:
                return CommandResult(False, "No encontré esa ventana abierta.")
            con, gui, _process = self._modules()
            gui.ShowWindow(window.handle, con.SW_RESTORE)
            gui.SetForegroundWindow(window.handle)
            self._previous_handle = self._active_handle
            self._active_handle = window.handle
            return CommandResult(True, f"Cambié a {window.title}.")
        except (WindowManagerError, OSError):
            return CommandResult(False, "Windows no permitió enfocar esa ventana.")

    def focus_previous_window(self) -> CommandResult:
        try:
            previous = self._previous_handle
            if previous is None or self._info(previous) is None:
                return CommandResult(False, "No tengo una ventana anterior registrada.")
            con, gui, _process = self._modules()
            window = self._info(previous)
            if window is None:
                return CommandResult(False, "No encontré la ventana anterior.")
            current = self._active_handle
            gui.ShowWindow(window.handle, con.SW_RESTORE)
            gui.SetForegroundWindow(window.handle)
            self._active_handle = window.handle
            self._previous_handle = current
            return CommandResult(True, f"Volví a {window.title}.")
        except (WindowManagerError, OSError):
            return CommandResult(False, "Windows no permitió cambiar a la ventana anterior.")

    def minimize_window(self, target: str | None) -> CommandResult:
        return self._show(target, "minimize")

    def maximize_window(self, target: str | None) -> CommandResult:
        return self._show(target, "maximize")

    def restore_window(self, target: str | None) -> CommandResult:
        return self._show(target, "restore")

    def _show(self, target: str | None, operation: str) -> CommandResult:
        try:
            window = self.find_window(target)
            if window is None:
                return CommandResult(False, "No encontré esa ventana abierta.")
            con, gui, _process = self._modules()
            commands = {"minimize": con.SW_MINIMIZE, "maximize": con.SW_MAXIMIZE, "restore": con.SW_RESTORE}
            gui.ShowWindow(window.handle, commands[operation])
            labels = {"minimize": "Minimicé", "maximize": "Maximicé", "restore": "Restauré"}
            return CommandResult(True, f"{labels[operation]} {window.title}.")
        except (WindowManagerError, OSError):
            return CommandResult(False, "Windows no permitió modificar esa ventana.")

    def wait_for_window(self, target: str | None, timeout: float = 8.0) -> WindowInfo | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            window = self.find_window(target)
            if window is not None:
                return window
            time.sleep(0.2)
        return None
