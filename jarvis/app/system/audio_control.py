from __future__ import annotations

import platform

from app.commands.base import CommandResult


class VolumeValidationError(ValueError):
    """A volume request is outside the safe range."""


def validate_volume(level: int) -> int:
    if not 0 <= level <= 100:
        raise VolumeValidationError("El volumen debe estar entre 0 y 100 %.")
    return level


class AudioController:
    def _device(self):
        if platform.system() != "Windows":
            raise RuntimeError("El control de volumen solo está disponible en Windows.")
        from pycaw.pycaw import AudioUtilities

        return AudioUtilities.GetSpeakers()

    @staticmethod
    def _get_percent(device: object) -> int:
        endpoint = device.EndpointVolume
        return round(float(endpoint.GetMasterVolumeLevelScalar()) * 100)

    @staticmethod
    def _set_percent(device: object, level: int) -> None:
        endpoint = device.EndpointVolume
        endpoint.SetMasterVolumeLevelScalar(level / 100, None)

    def set_volume(self, level: int) -> CommandResult:
        try:
            safe_level = validate_volume(level)
            device = self._device()
            self._set_percent(device, safe_level)
            if safe_level > 0:
                device.EndpointVolume.SetMute(0, None)
        except VolumeValidationError as error:
            return CommandResult(False, str(error))
        except Exception:
            return CommandResult(False, "No pude cambiar el volumen del sistema.")
        return CommandResult(True, f"Volumen ajustado a {safe_level} %.")

    def volume_up(self, step: int = 10) -> CommandResult:
        try:
            device = self._device()
            target = min(100, self._get_percent(device) + step)
        except Exception:
            return CommandResult(False, "No pude leer el volumen del sistema.")
        return self.set_volume(target)

    def volume_down(self, step: int = 10) -> CommandResult:
        try:
            device = self._device()
            target = max(0, self._get_percent(device) - step)
        except Exception:
            return CommandResult(False, "No pude leer el volumen del sistema.")
        return self.set_volume(target)

    def set_mute(self, muted: bool) -> CommandResult:
        try:
            device = self._device()
            device.EndpointVolume.SetMute(1 if muted else 0, None)
        except Exception:
            return CommandResult(False, "No pude cambiar el estado de sonido.")
        return CommandResult(True, "Computador silenciado." if muted else "Sonido activado.")
