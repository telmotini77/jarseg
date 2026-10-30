from __future__ import annotations

from abc import ABC, abstractmethod
import json
from typing import Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from openai import APIConnectionError, AuthenticationError, OpenAI, RateLimitError

from app.ai.prompts import SYSTEM_PROMPT
from app.core.config import Settings


class AIProviderError(RuntimeError):
    """An AI provider could not return a valid response."""


class AIProvider(ABC):
    @abstractmethod
    def generate_response(self, history: Sequence[dict[str, str]]) -> str:
        """Generate a response from bounded conversation history."""


class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise AIProviderError("Falta OPENAI_API_KEY. Configúrala en el archivo .env.")
        self._client = OpenAI(api_key=api_key)
        self._model = model

    def generate_response(self, history: Sequence[dict[str, str]]) -> str:
        try:
            completion = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}, *history],
            )
            response = completion.choices[0].message.content or ""
        except AuthenticationError as error:
            raise AIProviderError(
                "La clave de OpenAI no es válida. Reemplaza OPENAI_API_KEY en .env por una clave API real."
            ) from error
        except RateLimitError as error:
            raise AIProviderError("OpenAI rechazó la solicitud por cuota o límite de uso.") from error
        except APIConnectionError as error:
            raise AIProviderError("No se pudo conectar con OpenAI. Revisa la conexión a Internet.") from error
        except Exception as error:
            raise AIProviderError("No se pudo obtener una respuesta del proveedor de IA.") from error
        if not response.strip():
            raise AIProviderError("El proveedor de IA devolvió una respuesta vacía.")
        return response.strip()


class LocalProvider(AIProvider):
    """Small offline fallback for validating the voice loop without an API key."""

    def generate_response(self, history: Sequence[dict[str, str]]) -> str:
        question = history[-1]["content"] if history else ""
        return (
            "Estoy en modo local de prueba, por lo que no puedo generar una respuesta "
            f"completa a: {question}. Configura OPENAI_API_KEY y AI_PROVIDER=openai para usar IA."
        )


class OllamaProvider(AIProvider):
    """Runs an LLM through Ollama's local HTTP API without cloud credentials."""

    def __init__(self, model: str, host: str, timeout_seconds: int) -> None:
        if not model:
            raise AIProviderError("OLLAMA_MODEL no puede estar vacío.")
        self._model = model
        self._host = host.rstrip("/")
        self._timeout_seconds = timeout_seconds

    def validate(self) -> None:
        """Verify that the local runtime and selected model are ready before listening."""
        request = Request(f"{self._host}/api/tags", method="GET")
        try:
            with urlopen(request, timeout=min(self._timeout_seconds, 5)) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            raise AIProviderError(
                "Ollama local no está disponible. Instálalo e inícialo antes de ejecutar JARVIS."
            ) from error
        available_models = {
            item.get("name") for item in body.get("models", []) if isinstance(item, dict) and item.get("name")
        }
        if self._model not in available_models and f"{self._model}:latest" not in available_models:
            raise AIProviderError(
                f"El modelo local '{self._model}' no está instalado. Ejecuta: ollama pull {self._model}"
            )

    def generate_response(self, history: Sequence[dict[str, str]]) -> str:
        payload = json.dumps(
            {
                "model": self._model,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}, *history],
                "stream": False,
                "options": {"num_predict": 96, "temperature": 0.3},
            }
        ).encode("utf-8")
        request = Request(
            f"{self._host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 404:
                raise AIProviderError(
                    f"El modelo local '{self._model}' no está disponible. Ejecuta: ollama pull {self._model}"
                ) from error
            raise AIProviderError("Ollama rechazó la solicitud local.") from error
        except (URLError, TimeoutError) as error:
            raise AIProviderError(
                "No se pudo conectar con Ollama local. Instálalo e inícialo antes de ejecutar JARVIS."
            ) from error
        except (json.JSONDecodeError, OSError) as error:
            raise AIProviderError("Ollama devolvió una respuesta local no válida.") from error

        content = body.get("message", {}).get("content", "")
        if not isinstance(content, str) or not content.strip():
            raise AIProviderError("El modelo local devolvió una respuesta vacía.")
        return content.strip()


def create_ai_provider(settings: Settings) -> AIProvider:
    if settings.ai_provider == "local":
        return LocalProvider()
    if settings.ai_provider == "ollama":
        provider = OllamaProvider(settings.ollama_model, settings.ollama_host, settings.ollama_timeout_seconds)
        provider.validate()
        return provider
    return OpenAIProvider(settings.openai_api_key, settings.openai_model)
