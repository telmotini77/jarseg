"""Safe desktop input backend for the non-interactive JARVIS service."""

from __future__ import annotations

from types import SimpleNamespace


class HeadlessDesktopBackend:
    """Satisfy input-controller queries without granting a container desktop control."""

    _MESSAGE = "El servicio en segundo plano no controla el escritorio del equipo."

    def size(self) -> SimpleNamespace:
        return SimpleNamespace(width=1, height=1)

    def position(self) -> SimpleNamespace:
        return SimpleNamespace(x=0, y=0)

    def moveTo(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(self._MESSAGE)

    def click(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(self._MESSAGE)

    def scroll(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(self._MESSAGE)

    def write(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(self._MESSAGE)

    def press(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(self._MESSAGE)

    def hotkey(self, *args: object, **kwargs: object) -> None:
        raise RuntimeError(self._MESSAGE)
