from __future__ import annotations

from abc import ABC, abstractmethod
import re

from app.voice.microphone import Microphone
from app.voice.speech_to_text import SpeechToTextProvider
from app.voice.wake_word import extract_wake_command


class WakeWordError(RuntimeError):
    """A wake-word provider could not continue listening."""


class WakeWordProvider(ABC):
    @abstractmethod
    def wait_for_wake_word(self) -> bool: ...

    @abstractmethod
    def capture_command(self, timeout: int) -> str | None: ...

    @abstractmethod
    def suspend(self) -> None: ...

    @abstractmethod
    def resume(self) -> None: ...


class TranscriptWakeWordProvider(WakeWordProvider):
    """Detects the spoken word in transcribed audio and isolates the following command.

    It is intentionally replaceable by an acoustic local provider such as Porcupine.
    """

    def __init__(
        self,
        microphone: Microphone,
        stt: SpeechToTextProvider,
        listen_timeout: int,
        phrase_time_limit: int,
        wake_word: str = "jarvis",
    ) -> None:
        self._microphone = microphone
        self._stt = stt
        self._listen_timeout = listen_timeout
        self._phrase_time_limit = phrase_time_limit
        self._pending_command: str | None = None
        self._suspended = False
        self._wake_word = wake_word.casefold()

    def wait_for_wake_word(self) -> bool:
        if self._suspended:
            return False
        audio = self._microphone.listen(self._listen_timeout, self._phrase_time_limit)
        if audio is None:
            return False
        transcript = self._stt.transcribe(audio)
        command = extract_wake_command(transcript) if self._wake_word == "jarvis" else self._extract_custom_command(transcript)
        if command is None:
            return False
        self._pending_command = command
        return True

    def capture_command(self, timeout: int) -> str | None:
        if self._pending_command and self._pending_command.casefold() != "jarvis":
            command, self._pending_command = self._pending_command, None
            return command
        self._pending_command = None
        if self._suspended:
            return None
        audio = self._microphone.listen(timeout, self._phrase_time_limit)
        if audio is None:
            return None
        transcript = self._stt.transcribe(audio).strip()
        return f"Jarvis {transcript}" if transcript else None

    def suspend(self) -> None:
        self._suspended = True

    def resume(self) -> None:
        self._suspended = False

    def _extract_custom_command(self, transcript: str) -> str | None:
        match = re.match(rf"^\s*{re.escape(self._wake_word)}\b[\s,;:.-]*(.*)$", transcript, re.IGNORECASE)
        if match is None:
            return None
        command = match.group(1).strip()
        return self._wake_word.title() if not command else f"{self._wake_word.title()} {command}"
