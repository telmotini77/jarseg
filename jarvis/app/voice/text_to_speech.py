from __future__ import annotations

from abc import ABC, abstractmethod
import platform
from pathlib import Path
import tempfile
import threading
from urllib.error import URLError
from urllib.request import urlretrieve
import wave

import pyttsx3


class TextToSpeechError(RuntimeError):
    """Speech synthesis failed."""


class TextToSpeechProvider(ABC):
    @abstractmethod
    def speak(self, text: str) -> None:
        """Speak text through the configured output device."""

    @abstractmethod
    def close(self) -> None:
        """Release any provider resources."""


class Pyttsx3Provider(TextToSpeechProvider):
    def __init__(self, rate: int, voice_hint: str = "", volume: float = 1.0) -> None:
        self._sapi_voice: object | None = None
        try:
            if platform.system() == "Windows":
                from comtypes.client import CreateObject

                self._sapi_voice = CreateObject("SAPI.SpVoice")
                self._sapi_voice.Volume = round(volume * 100)
                self._sapi_voice.Rate = max(-10, min(10, round((rate - 175) / 10)))
                if voice_hint:
                    self._select_sapi_voice(voice_hint)
                else:
                    self._select_sapi_voice("spanish")
                return

            self._engine = pyttsx3.init()
            self._engine.setProperty("rate", rate)
            self._engine.setProperty("volume", volume)
            if voice_hint:
                self._select_voice(voice_hint)
            else:
                self._select_spanish_voice()
        except Exception as error:
            raise TextToSpeechError("No se pudo inicializar el motor de voz.") from error

    def _select_sapi_voice(self, hint: str) -> None:
        if self._sapi_voice is None:
            return
        for index in range(self._sapi_voice.GetVoices().Count):
            candidate = self._sapi_voice.GetVoices().Item(index)
            if hint.lower() in candidate.GetDescription().lower():
                self._sapi_voice.Voice = candidate
                return

    def _select_voice(self, hint: str) -> None:
        for voice in self._engine.getProperty("voices"):
            if hint.lower() in f"{voice.name} {voice.id}".lower():
                self._engine.setProperty("voice", voice.id)
                return

    def _select_spanish_voice(self) -> None:
        for voice in self._engine.getProperty("voices"):
            languages = " ".join(str(item) for item in getattr(voice, "languages", []))
            description = f"{voice.name} {voice.id} {languages}".lower()
            if any(marker in description for marker in ("spanish", "español", "espanol", "es-")):
                self._engine.setProperty("voice", voice.id)
                return

    def speak(self, text: str) -> None:
        if not text.strip():
            return
        try:
            if self._sapi_voice is not None:
                self._sapi_voice.Speak(text)
                return
            self._engine.say(text)
            self._engine.runAndWait()
        except Exception as error:
            raise TextToSpeechError("No se pudo reproducir la respuesta por voz.") from error

    def close(self) -> None:
        try:
            if self._sapi_voice is not None:
                self._sapi_voice.Speak("", 3)
                self._sapi_voice = None
                return
            self._engine.stop()
        except Exception:
            pass


class PiperTTSProvider(TextToSpeechProvider):
    """Offline neural Spanish voice backed by the free DaveFX Piper model.

    The model is downloaded once from its public CC0 repository through HTTPS,
    then all synthesis remains local on the computer.
    """

    _MODEL_URL = "https://huggingface.co/Trelis/piper-es-es-davefx-medium/resolve/main/model.onnx"
    _CONFIG_URL = "https://huggingface.co/Trelis/piper-es-es-davefx-medium/resolve/main/model.onnx.json"

    def __init__(self, model_directory: Path, volume: float = 1.0) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._volume = volume  # Kept for a consistent provider interface.
        model_path, config_path = self._ensure_model(model_directory)
        try:
            from piper import PiperVoice

            self._voice = PiperVoice.load(model_path, config_path=config_path)
        except Exception as error:
            raise TextToSpeechError("No se pudo cargar la voz neuronal local de JARVIS.") from error

    @classmethod
    def _ensure_model(cls, directory: Path) -> tuple[Path, Path]:
        directory.mkdir(parents=True, exist_ok=True)
        model_path = directory / "model.onnx"
        config_path = directory / "model.onnx.json"
        for target, url in ((model_path, cls._MODEL_URL), (config_path, cls._CONFIG_URL)):
            if target.is_file() and target.stat().st_size > 0:
                continue
            temporary = target.with_suffix(target.suffix + ".part")
            try:
                urlretrieve(url, temporary)
                if not temporary.is_file() or temporary.stat().st_size == 0:
                    raise OSError("archivo de voz vacío")
                temporary.replace(target)
            except (OSError, URLError) as error:
                temporary.unlink(missing_ok=True)
                raise TextToSpeechError("No pude descargar la voz gratuita de JARVIS. Revisa tu conexión e inténtalo de nuevo.") from error
        return model_path, config_path

    def speak(self, text: str) -> None:
        if not text.strip() or self._closed:
            return
        path: Path | None = None
        with self._lock:
            try:
                with tempfile.NamedTemporaryFile(prefix="jarvis-voice-", suffix=".wav", delete=False) as output:
                    path = Path(output.name)
                with wave.open(str(path), "wb") as wav_file:
                    self._voice.synthesize_wav(text, wav_file)
                if platform.system() == "Windows":
                    import winsound

                    winsound.PlaySound(str(path), winsound.SND_FILENAME)
                else:
                    raise TextToSpeechError("La voz Piper integrada actualmente requiere Windows para reproducirse.")
            except TextToSpeechError:
                raise
            except Exception as error:
                raise TextToSpeechError("No se pudo reproducir la respuesta con la voz de JARVIS.") from error
            finally:
                if path is not None:
                    path.unlink(missing_ok=True)

    def close(self) -> None:
        self._closed = True
