from __future__ import annotations

from abc import ABC, abstractmethod
import base64
from dataclasses import dataclass, field
from io import BytesIO

from openai import APIConnectionError, AuthenticationError, OpenAI, RateLimitError
from PIL import Image

from app.vision.context import ScreenContext


class VisionProvider(ABC):
    """Interchangeable visual-analysis interface; providers receive images only on request."""

    @abstractmethod
    def analyze_image(self, image: Image.Image, question: str, context: ScreenContext) -> str:
        """Return a user-facing analysis of an explicitly requested capture."""


class VisionProviderError(RuntimeError):
    """A configured visual provider could not analyze the requested capture."""


@dataclass(slots=True)
class ContextVisionProvider(VisionProvider):
    """Local provider that reports desktop context without uploading any screenshot."""

    def analyze_image(self, image: Image.Image, question: str, context: ScreenContext) -> str:
        active_window = context.active_window or "ninguna ventana identificable"
        active_process = f" ({context.active_process})" if context.active_process else ""
        return (
            f"Capturé la pantalla de {image.width} por {image.height} píxeles. "
            f"La ventana activa es {active_window}{active_process}. "
            "El análisis visual detallado requiere conectar un proveedor de visión compatible; "
            "la captura no se ha enviado fuera del equipo."
        )


@dataclass(slots=True)
class OpenAIVisionProvider(VisionProvider):
    """Remote vision provider used only after an explicit screen-analysis command."""

    api_key: str
    model: str
    _client: OpenAI = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.api_key:
            raise VisionProviderError("Falta la clave necesaria para el proveedor de visión.")
        self._client = OpenAI(api_key=self.api_key)

    def analyze_image(self, image: Image.Image, question: str, context: ScreenContext) -> str:
        image_data = BytesIO()
        image.save(image_data, format="PNG")
        encoded_image = base64.b64encode(image_data.getvalue()).decode("ascii")
        prompt = (
            "Responde en español, de forma breve y útil. Analiza solo la imagen que el usuario "
            "solicitó compartir. No ejecutes acciones ni inventes contenido. "
            f"Ventana activa detectada: {context.active_window or 'desconocida'}. "
            f"Pregunta del usuario: {question or 'Describe qué se ve en pantalla.'}"
        )
        try:
            completion = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{encoded_image}"}},
                        ],
                    }
                ],
            )
            response = completion.choices[0].message.content or ""
        except AuthenticationError as error:
            raise VisionProviderError("El proveedor de visión rechazó las credenciales configuradas.") from error
        except RateLimitError as error:
            raise VisionProviderError("El proveedor de visión alcanzó su límite de uso.") from error
        except APIConnectionError as error:
            raise VisionProviderError("No pude conectar con el proveedor de visión.") from error
        except Exception as error:
            raise VisionProviderError("No pude analizar la captura solicitada.") from error
        if not response.strip():
            raise VisionProviderError("El proveedor de visión no devolvió una respuesta.")
        return response.strip()
