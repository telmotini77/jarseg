from __future__ import annotations

from abc import ABC, abstractmethod

import speech_recognition as sr


class SpeechToTextError(RuntimeError):
    """Audio could not be transcribed."""


class SpeechToTextProvider(ABC):
    @abstractmethod
    def transcribe(self, audio: sr.AudioData) -> str:
        """Return the recognized text."""


class GoogleSpeechRecognitionProvider(SpeechToTextProvider):
    def __init__(self, language: str) -> None:
        self._recognizer = sr.Recognizer()
        self._language = language

    def transcribe(self, audio: sr.AudioData) -> str:
        try:
            text = self._recognizer.recognize_google(audio, language=self._language)
        except sr.UnknownValueError as error:
            raise SpeechToTextError("No se detectó voz comprensible.") from error
        except sr.RequestError as error:
            raise SpeechToTextError("El servicio de transcripción no está disponible. Revisa Internet.") from error
        if not text.strip():
            raise SpeechToTextError("La transcripción está vacía.")
        return text.strip()
