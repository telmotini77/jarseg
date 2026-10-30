import logging
from unittest.mock import MagicMock, patch

from app.ai.provider import AIProvider, AIProviderError, OllamaProvider, OpenAIProvider
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis


class FakeProvider(AIProvider):
    def generate_response(self, history: list[dict[str, str]]) -> str:
        return "respuesta de prueba"


def test_exit_command_stops_jarvis() -> None:
    jarvis = Jarvis(FakeProvider(), ConversationManager(), CommandRouter(), logging.getLogger("test"))
    result = jarvis.process("Jarvis salir")
    assert result.should_exit is True
    assert "Cerrando" in result.response


def test_openai_provider_requires_an_api_key() -> None:
    try:
        OpenAIProvider("", "gpt-4.1-mini")
    except AIProviderError as error:
        assert "OPENAI_API_KEY" in str(error)
    else:
        raise AssertionError("Expected an API key configuration error")


def test_ollama_provider_reads_a_local_chat_response() -> None:
    response = MagicMock()
    response.read.return_value = b'{"message": {"content": "Respuesta local"}}'
    response.__enter__.return_value = response
    with patch("app.ai.provider.urlopen", return_value=response):
        result = OllamaProvider("llama3.2", "http://127.0.0.1:11434", 10).generate_response(
            [{"role": "user", "content": "Hola"}]
        )
    assert result == "Respuesta local"


def test_ollama_provider_reports_missing_runtime() -> None:
    with patch("app.ai.provider.urlopen", side_effect=TimeoutError):
        try:
            OllamaProvider("llama3.2", "http://127.0.0.1:11434", 10).validate()
        except AIProviderError as error:
            assert "no está disponible" in str(error)
        else:
            raise AssertionError("Expected an unavailable Ollama runtime error")
