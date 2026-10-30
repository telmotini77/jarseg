import pytest

from app.core.config import ConfigurationError, Settings


def test_settings_default_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.config.load_dotenv", lambda: None)
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("MICROPHONE_INDEX", raising=False)
    settings = Settings.from_env()
    assert settings.ai_provider == "openai"
    assert settings.microphone_index is None
    assert settings.chrome_profile == "last_used"
    assert settings.tts_volume == 1.0
    assert settings.tts_provider == "piper"
    assert settings.tts_piper_model_dir == "data/voices/davefx"
    assert settings.memory_mode == "explicit_only"
    assert settings.timezone == "America/Guayaquil"
    assert settings.wake_word_enabled is True
    assert settings.browser_provider == "playwright"
    assert settings.browser_channel == "chrome"
    assert settings.browser_headless is False
    assert settings.browser_profile_dir == "data/browser-profile"
    assert settings.terminal_mode == "confirm"
    assert settings.terminal_default_timeout == 60
    assert settings.code_agent_enabled is True
    assert settings.code_agent_mode == "assist"
    assert settings.code_max_fix_attempts == 3
    assert settings.project_builder_enabled is True
    assert settings.project_builder_root == "data/generated-projects"
    assert settings.dashboard_enabled is False
    assert settings.dashboard_auto_open is False
    assert settings.telegram_enabled is False
    assert settings.telegram_timeout_seconds == 3
    assert settings.cyberseg_enabled is False
    assert settings.cyberseg_api_url == "http://127.0.0.1:8780"
    assert settings.cyberseg_monitor_enabled is False
    assert settings.cyberseg_monitor_poll_seconds == 15
    assert settings.cyberseg_monitor_retry_attempts == 2
    assert settings.cyberseg_monitor_failure_threshold == 3
    assert settings.cyberseg_monitor_min_risk == "high"
    assert settings.cyberseg_monitor_clean_report_seconds == 86_400
    assert settings.cyberseg_monitor_notify_service_state is False
    assert settings.cyberseg_deployment_profile == "desktop"
    assert settings.cyberseg_server_auto_block is False


def test_settings_rejects_unknown_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER", "unknown")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_accepts_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.2")
    settings = Settings.from_env()
    assert settings.ai_provider == "ollama"
    assert settings.ollama_model == "llama3.2"


def test_settings_can_disable_text_to_speech(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TTS_ENABLED", "false")
    assert Settings.from_env().tts_enabled is False


def test_settings_rejects_invalid_text_to_speech_volume(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TTS_VOLUME", "1.1")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_rejects_unknown_text_to_speech_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TTS_PROVIDER", "cloud")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_rejects_unsafe_chrome_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHROME_PROFILE", "..\\other-profile")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_rejects_invalid_memory_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEMORY_MODE", "everything")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_rejects_unknown_browser_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_PROVIDER", "selenium")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_accepts_supported_search_engines(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_DEFAULT_SEARCH_ENGINE", "duckduckgo")
    assert Settings.from_env().browser_default_search_engine == "duckduckgo"


def test_settings_rejects_unknown_browser_channel(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BROWSER_CHANNEL", "edge")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_rejects_unknown_terminal_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TERMINAL_MODE", "unsafe")
    with pytest.raises(ConfigurationError):
        Settings.from_env()


def test_settings_rejects_unknown_code_agent_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODE_AGENT_MODE", "unrestricted")
    with pytest.raises(ConfigurationError):
        Settings.from_env()
    monkeypatch.setenv("BROWSER_PROVIDER", "playwright")
    monkeypatch.setenv("BROWSER_DEFAULT_SEARCH_ENGINE", "bing")
    with pytest.raises(ConfigurationError):
        Settings.from_env()
