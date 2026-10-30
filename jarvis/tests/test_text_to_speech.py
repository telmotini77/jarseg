from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.voice.text_to_speech import PiperTTSProvider, Pyttsx3Provider


def test_windows_sapi_speaks_through_the_native_voice() -> None:
    provider = object.__new__(Pyttsx3Provider)
    provider._sapi_voice = MagicMock()

    provider.speak("Prueba de voz")

    provider._sapi_voice.Speak.assert_called_once_with("Prueba de voz")


def test_piper_provider_downloads_model_and_config_to_its_local_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_download(_url: str, destination: Path) -> tuple[str, None]:
        destination.write_bytes(b"voice data")
        return str(destination), None

    monkeypatch.setattr("app.voice.text_to_speech.urlretrieve", fake_download)
    model, config = PiperTTSProvider._ensure_model(tmp_path)
    assert model.name == "model.onnx"
    assert config.name == "model.onnx.json"
    assert model.read_bytes() == b"voice data"
    assert config.read_bytes() == b"voice data"
