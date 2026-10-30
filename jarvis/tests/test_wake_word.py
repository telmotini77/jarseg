from app.voice.wake_word import extract_wake_command


def test_extracts_command_that_starts_with_jarvis() -> None:
    assert extract_wake_command("Jarvis abre Chrome") == "Jarvis abre Chrome"


def test_accepts_common_javis_transcription_variant() -> None:
    assert extract_wake_command("javis, busca MQTT ESP32") == "Jarvis busca MQTT ESP32"
    assert extract_wake_command("yarvis abre YouTube en Chrome") == "Jarvis abre YouTube en Chrome"


def test_ignores_phrase_without_wake_word_at_the_start() -> None:
    assert extract_wake_command("abre Chrome") is None
    assert extract_wake_command("hola Jarvis abre Chrome") is None
