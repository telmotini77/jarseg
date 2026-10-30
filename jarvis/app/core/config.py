from __future__ import annotations

from dataclasses import dataclass
from os import getenv
import re
from typing import Optional
from urllib.parse import urlparse

from dotenv import load_dotenv


class ConfigurationError(ValueError):
    """Raised when an environment setting is invalid."""


def _positive_int(name: str, default: int) -> int:
    value = getenv(name, str(default))
    try:
        parsed = int(value)
    except ValueError as error:
        raise ConfigurationError(f"{name} debe ser un número entero.") from error
    if parsed <= 0:
        raise ConfigurationError(f"{name} debe ser mayor que cero.")
    return parsed


def _optional_int(name: str) -> Optional[int]:
    value = getenv(name, "").strip()
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError as error:
        raise ConfigurationError(f"{name} debe ser un número entero o estar vacío.") from error
    if parsed < 0:
        raise ConfigurationError(f"{name} no puede ser negativo.")
    return parsed


def _boolean(name: str, default: bool) -> bool:
    value = getenv(name, str(default)).strip().lower()
    if value in {"1", "true", "yes", "si", "sí", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} debe ser true o false.")


def _unit_interval(name: str, default: float) -> float:
    value = getenv(name, str(default))
    try:
        parsed = float(value)
    except ValueError as error:
        raise ConfigurationError(f"{name} debe ser un número entre 0 y 1.") from error
    if not 0 <= parsed <= 1:
        raise ConfigurationError(f"{name} debe estar entre 0 y 1.")
    return parsed


def _chrome_profile() -> str:
    value = getenv("CHROME_PROFILE", "last_used").strip()
    if value == "last_used" or re.fullmatch(r"(?:Default|Profile [0-9]+)", value):
        return value
    raise ConfigurationError("CHROME_PROFILE debe ser 'last_used', 'Default' o 'Profile N'.")


def _memory_mode() -> str:
    value = getenv("MEMORY_MODE", "explicit_only").strip().lower()
    if value not in {"explicit_only", "smart", "disabled"}:
        raise ConfigurationError("MEMORY_MODE debe ser explicit_only, smart o disabled.")
    return value


def _memory_embedding_provider() -> str:
    value = getenv("MEMORY_EMBEDDING_PROVIDER", "local_hash").strip().lower()
    if value != "local_hash":
        raise ConfigurationError("MEMORY_EMBEDDING_PROVIDER disponible: local_hash.")
    return value


def _timezone() -> str:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    value = getenv("TIMEZONE", "America/Guayaquil").strip()
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as error:
        raise ConfigurationError("TIMEZONE debe ser una zona horaria IANA válida.") from error
    return value


def _wake_word_provider() -> str:
    value = getenv("WAKE_WORD_PROVIDER", "transcript").strip().lower()
    if value != "transcript":
        raise ConfigurationError("WAKE_WORD_PROVIDER disponible: transcript.")
    return value


def _tts_provider() -> str:
    value = getenv("TTS_PROVIDER", "piper").strip().lower()
    if value not in {"piper", "sapi"}:
        raise ConfigurationError("TTS_PROVIDER debe ser 'piper' o 'sapi'.")
    return value


def _browser_provider() -> str:
    value = getenv("BROWSER_PROVIDER", "playwright").strip().lower()
    if value != "playwright":
        raise ConfigurationError("BROWSER_PROVIDER disponible: playwright.")
    return value


def _browser_channel() -> str:
    """Select the visible browser binary controlled by Playwright.

    Chrome runs with JARVIS' own profile directory, never the user's personal
    browser profile. Chromium remains available as a portable fallback.
    """
    value = getenv("BROWSER_CHANNEL", "chrome").strip().lower()
    if value not in {"chrome", "chromium"}:
        raise ConfigurationError("BROWSER_CHANNEL debe ser 'chrome' o 'chromium'.")
    return value


def _browser_search_engine() -> str:
    value = getenv("BROWSER_DEFAULT_SEARCH_ENGINE", "google").strip().lower()
    if value not in {"google", "bing", "duckduckgo", "youtube"}:
        raise ConfigurationError("BROWSER_DEFAULT_SEARCH_ENGINE admite google, bing, duckduckgo o youtube.")
    return value


def _terminal_mode() -> str:
    value = getenv("TERMINAL_MODE", "confirm").strip().lower()
    if value not in {"read_only", "confirm", "execute"}:
        raise ConfigurationError("TERMINAL_MODE debe ser read_only, confirm o execute.")
    return value


def _code_agent_mode() -> str:
    value = getenv("CODE_AGENT_MODE", "assist").strip().lower()
    if value not in {"read_only", "assist", "auto_fix"}:
        raise ConfigurationError("CODE_AGENT_MODE debe ser read_only, assist o auto_fix.")
    return value


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise ConfigurationError(f"{name} debe ser un número entero.") from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} debe estar entre {minimum} y {maximum}.")
    return value


def _bounded_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as error:
        raise ConfigurationError(f"{name} debe ser un número.") from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} debe estar entre {minimum} y {maximum}.")
    return value


def _mqtt_topic_prefix() -> str:
    value = getenv("MQTT_TOPIC_PREFIX", "jarvis").strip().strip("/")
    if not value or any(marker in value for marker in ("#", "+", "..", "//")):
        raise ConfigurationError("MQTT_TOPIC_PREFIX no puede contener comodines ni rutas ambiguas.")
    return value


def _orchestrator_mode() -> str:
    value = getenv("ORCHESTRATOR_MODE", "assist").strip().lower()
    if value not in {"read_only", "assist", "autonomous_safe"}:
        raise ConfigurationError("ORCHESTRATOR_MODE debe ser read_only, assist o autonomous_safe.")
    return value


def _automation_misfire_policy() -> str:
    value = getenv("AUTOMATION_MISFIRE_POLICY", "skip").strip().lower()
    if value not in {"skip", "run_on_start"}:
        raise ConfigurationError("AUTOMATION_MISFIRE_POLICY debe ser skip o run_on_start.")
    return value


def _dashboard_host() -> str:
    value = getenv("DASHBOARD_HOST", "127.0.0.1").strip()
    if value not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
        raise ConfigurationError("DASHBOARD_HOST solo admite 127.0.0.1, localhost, ::1 o 0.0.0.0 en v1.1.")
    return value


def _cyberseg_api_url() -> str:
    value = getenv("CYBERSEG_API_URL", "http://127.0.0.1:8780").strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1", "host.docker.internal"}:
        raise ConfigurationError("CYBERSEG_API_URL debe usar HTTP(S) local: 127.0.0.1, localhost, ::1 o host.docker.internal.")
    return value


def _cyberseg_deployment_profile() -> str:
    value = getenv("CYBERSEG_DEPLOYMENT_PROFILE", "desktop").strip().lower()
    if value not in {"desktop", "server"}:
        raise ConfigurationError("CYBERSEG_DEPLOYMENT_PROFILE debe ser 'desktop' o 'server'.")
    return value


def _cyberseg_firewall() -> str:
    value = getenv("CYBERSEG_SERVER_FIREWALL", "auto").strip().lower()
    if value not in {"auto", "ufw", "firewalld", "nftables", "iptables"}:
        raise ConfigurationError("CYBERSEG_SERVER_FIREWALL debe ser auto, ufw, firewalld, nftables o iptables.")
    return value


def _cyberseg_minimum_risk() -> str:
    value = getenv("CYBERSEG_SERVER_MIN_RISK", "high").strip().lower()
    if value not in {"high", "critical"}:
        raise ConfigurationError("CYBERSEG_SERVER_MIN_RISK debe ser high o critical.")
    return value


def _cyberseg_monitor_minimum_risk() -> str:
    value = getenv("CYBERSEG_MONITOR_MIN_RISK", "high").strip().lower()
    if value not in {"low", "medium", "high", "critical"}:
        raise ConfigurationError("CYBERSEG_MONITOR_MIN_RISK debe ser low, medium, high o critical.")
    return value


def _csv_values(name: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in getenv(name, "").split(",") if value.strip())


@dataclass(frozen=True, slots=True)
class Settings:
    ai_provider: str
    openai_api_key: str
    openai_model: str
    ollama_model: str
    ollama_host: str
    ollama_timeout_seconds: int
    stt_language: str
    microphone_index: Optional[int]
    listen_timeout: int
    phrase_time_limit: int
    ambient_noise_duration: float
    max_conversation_turns: int
    tts_rate: int
    tts_volume: float
    tts_voice_hint: str
    tts_enabled: bool
    tts_provider: str
    tts_piper_model_dir: str
    chrome_profile: str
    memory_enabled: bool
    memory_mode: str
    memory_max_results: int
    memory_database: str
    memory_embedding_provider: str
    memory_context_max_items: int
    memory_context_max_tokens: int
    memory_encryption_enabled: bool
    memory_encryption_key: str
    memory_session_restore: bool
    scheduler_enabled: bool
    timezone: str
    wake_word_enabled: bool
    wake_word: str
    wake_word_provider: str
    wake_command_timeout: int
    browser_provider: str
    browser_channel: str
    browser_headless: bool
    browser_default_search_engine: str
    browser_timeout: int
    browser_profile_dir: str
    terminal_enabled: bool
    terminal_mode: str
    terminal_default_timeout: int
    terminal_max_output: int
    terminal_allow_powershell: bool
    terminal_allow_cmd: bool
    terminal_managed_processes: bool
    code_agent_enabled: bool
    code_agent_mode: str
    code_max_files: int
    code_max_file_size: int
    code_max_total_bytes: int
    code_max_context_tokens: int
    code_max_fix_attempts: int
    code_project_sandbox: bool
    code_respect_gitignore: bool
    code_auto_run_tests: bool
    code_auto_run_lint: bool
    project_builder_enabled: bool
    project_builder_root: str
    project_builder_max_files: int
    project_builder_max_file_chars: int
    vscode_integration_enabled: bool
    iot_enabled: bool
    mqtt_broker_host: str
    mqtt_broker_port: int
    mqtt_username: str
    mqtt_password: str
    mqtt_use_tls: bool
    mqtt_client_id: str
    mqtt_keepalive: int
    mqtt_default_qos: int
    mqtt_reconnect_enabled: bool
    mqtt_reconnect_max_seconds: int
    mqtt_topic_prefix: str
    mqtt_max_payload_bytes: int
    iot_telemetry_retention_days: int
    iot_command_timeout: int
    iot_rule_cooldown_seconds: int
    iot_default_device: str
    iot_verbose_telemetry_log: bool
    orchestrator_enabled: bool
    orchestrator_mode: str
    orchestrator_max_retries: int
    orchestrator_max_replans: int
    orchestrator_max_parallel_tasks: int
    automation_engine_enabled: bool
    automation_max_actions: int
    automation_cooldown_seconds: int
    automation_poll_seconds: int
    automation_misfire_policy: str
    telegram_enabled: bool
    telegram_bot_token: str
    telegram_chat_id: str
    telegram_timeout_seconds: int
    telegram_retry_attempts: int
    telegram_queue_size: int
    telegram_deduplication_seconds: int
    cyberseg_enabled: bool
    cyberseg_api_url: str
    cyberseg_api_token: str
    cyberseg_timeout_seconds: int
    cyberseg_http_retry_attempts: int
    cyberseg_http_retry_backoff_seconds: float
    cyberseg_monitor_enabled: bool
    cyberseg_monitor_poll_seconds: int
    cyberseg_monitor_max_poll_seconds: int
    cyberseg_monitor_retry_attempts: int
    cyberseg_monitor_failure_threshold: int
    cyberseg_monitor_min_risk: str
    cyberseg_monitor_clean_report_seconds: int
    cyberseg_monitor_notify_existing: bool
    cyberseg_monitor_notify_service_state: bool
    cyberseg_deployment_profile: str
    cyberseg_server_auto_block: bool
    cyberseg_server_firewall: str
    cyberseg_server_min_risk: str
    cyberseg_server_allowlist: tuple[str, ...]
    cyberseg_server_allow_private_sources: bool
    dashboard_enabled: bool
    dashboard_host: str
    dashboard_port: int
    dashboard_auto_open: bool
    dashboard_ws_enabled: bool
    dashboard_system_metrics_interval: int
    dashboard_telemetry_interval: int
    mobile_api_enabled: bool
    mobile_api_token: str
    productivity_enabled: bool
    google_integration_enabled: bool
    google_oauth_credentials_file: str
    google_oauth_token_file: str
    productivity_timezone: str
    users_enabled: bool
    user_auth_enabled: bool
    user_default_role: str
    user_auto_lock_minutes: int
    user_password_hasher: str
    multiuser_memory_isolation: bool
    multiuser_browser_profile_isolation: bool
    hud_enabled: bool
    hud_mode: str
    hud_particles: bool
    hud_target_fps: int
    hud_audio_visualizer: bool
    hud_agent_graph: bool
    hud_system_metrics: bool
    hud_auto_hide_conversation: bool
    desktop_overlay_enabled: bool
    system_tray_enabled: bool
    wake_sound_enabled: bool
    startup_sound_enabled: bool

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        provider = getenv("AI_PROVIDER", "openai").strip().lower()
        if provider not in {"openai", "ollama", "local"}:
            raise ConfigurationError("AI_PROVIDER debe ser 'openai', 'ollama' o 'local'.")
        try:
            ambient_noise_duration = float(getenv("AMBIENT_NOISE_DURATION", "0.5"))
        except ValueError as error:
            raise ConfigurationError("AMBIENT_NOISE_DURATION debe ser numérico.") from error
        if ambient_noise_duration < 0:
            raise ConfigurationError("AMBIENT_NOISE_DURATION no puede ser negativo.")
        return cls(
            ai_provider=provider,
            openai_api_key=getenv("OPENAI_API_KEY", "").strip(),
            openai_model=getenv("OPENAI_MODEL", "gpt-4.1-mini").strip(),
            ollama_model=getenv("OLLAMA_MODEL", "llama3.2").strip(),
            ollama_host=getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/"),
            ollama_timeout_seconds=_positive_int("OLLAMA_TIMEOUT_SECONDS", 120),
            stt_language=getenv("STT_LANGUAGE", "es-ES").strip(),
            microphone_index=_optional_int("MICROPHONE_INDEX"),
            listen_timeout=_positive_int("LISTEN_TIMEOUT", 8),
            phrase_time_limit=_positive_int("PHRASE_TIME_LIMIT", 20),
            ambient_noise_duration=ambient_noise_duration,
            max_conversation_turns=_positive_int("MAX_CONVERSATION_TURNS", 8),
            tts_rate=_positive_int("TTS_RATE", 185),
            tts_volume=_unit_interval("TTS_VOLUME", 1.0),
            tts_voice_hint=getenv("TTS_VOICE_HINT", "").strip(),
            tts_enabled=_boolean("TTS_ENABLED", True),
            tts_provider=_tts_provider(),
            tts_piper_model_dir=getenv("TTS_PIPER_MODEL_DIR", "data/voices/davefx").strip() or "data/voices/davefx",
            chrome_profile=_chrome_profile(),
            memory_enabled=_boolean("MEMORY_ENABLED", True),
            memory_mode=_memory_mode(),
            memory_max_results=_positive_int("MEMORY_MAX_RESULTS", 5),
            memory_database=getenv("MEMORY_DATABASE", "data/jarvis.db").strip() or "data/jarvis.db",
            memory_embedding_provider=_memory_embedding_provider(),
            memory_context_max_items=_positive_int("MEMORY_CONTEXT_MAX_ITEMS", 10),
            memory_context_max_tokens=_positive_int("MEMORY_CONTEXT_MAX_TOKENS", 600),
            memory_encryption_enabled=_boolean("MEMORY_ENCRYPTION_ENABLED", False),
            memory_encryption_key=getenv("MEMORY_ENCRYPTION_KEY", "").strip(),
            memory_session_restore=_boolean("MEMORY_SESSION_RESTORE", False),
            scheduler_enabled=_boolean("SCHEDULER_ENABLED", True),
            timezone=_timezone(),
            wake_word_enabled=_boolean("WAKE_WORD_ENABLED", True),
            wake_word=getenv("WAKE_WORD", "jarvis").strip().casefold() or "jarvis",
            wake_word_provider=_wake_word_provider(),
            wake_command_timeout=_positive_int("WAKE_COMMAND_TIMEOUT", 8),
            browser_provider=_browser_provider(),
            browser_channel=_browser_channel(),
            browser_headless=_boolean("BROWSER_HEADLESS", False),
            browser_default_search_engine=_browser_search_engine(),
            browser_timeout=_positive_int("BROWSER_TIMEOUT", 20),
            browser_profile_dir=getenv("BROWSER_PROFILE_DIR", "data/browser-profile").strip() or "data/browser-profile",
            terminal_enabled=_boolean("TERMINAL_ENABLED", True),
            terminal_mode=_terminal_mode(),
            terminal_default_timeout=_positive_int("TERMINAL_DEFAULT_TIMEOUT", 60),
            terminal_max_output=_positive_int("TERMINAL_MAX_OUTPUT", 12_000),
            terminal_allow_powershell=_boolean("TERMINAL_ALLOW_POWERSHELL", True),
            terminal_allow_cmd=_boolean("TERMINAL_ALLOW_CMD", True),
            terminal_managed_processes=_boolean("TERMINAL_MANAGED_PROCESSES", True),
            code_agent_enabled=_boolean("CODE_AGENT_ENABLED", True),
            code_agent_mode=_code_agent_mode(),
            code_max_files=_positive_int("CODE_MAX_FILES", 2_000),
            code_max_file_size=_positive_int("CODE_MAX_FILE_SIZE", 1_000_000),
            code_max_total_bytes=_positive_int("CODE_MAX_TOTAL_BYTES", 8_000_000),
            code_max_context_tokens=_positive_int("CODE_MAX_CONTEXT_TOKENS", 2_000),
            code_max_fix_attempts=_positive_int("CODE_MAX_FIX_ATTEMPTS", 3),
            code_project_sandbox=_boolean("CODE_PROJECT_SANDBOX", True),
            code_respect_gitignore=_boolean("CODE_RESPECT_GITIGNORE", True),
            code_auto_run_tests=_boolean("CODE_AUTO_RUN_TESTS", True),
            code_auto_run_lint=_boolean("CODE_AUTO_RUN_LINT", True),
            project_builder_enabled=_boolean("PROJECT_BUILDER_ENABLED", True),
            project_builder_root=getenv("PROJECT_BUILDER_ROOT", "data/generated-projects").strip() or "data/generated-projects",
            project_builder_max_files=_bounded_int("PROJECT_BUILDER_MAX_FILES", 20, 1, 50),
            project_builder_max_file_chars=_bounded_int("PROJECT_BUILDER_MAX_FILE_CHARS", 40_000, 1_000, 100_000),
            vscode_integration_enabled=_boolean("VSCODE_INTEGRATION_ENABLED", True),
            iot_enabled=_boolean("IOT_ENABLED", True),
            mqtt_broker_host=getenv("MQTT_BROKER_HOST", "broker.emqx.io").strip() or "broker.emqx.io",
            mqtt_broker_port=_bounded_int("MQTT_BROKER_PORT", 1883, 1, 65535),
            mqtt_username=getenv("MQTT_USERNAME", "").strip(),
            mqtt_password=getenv("MQTT_PASSWORD", ""),
            mqtt_use_tls=_boolean("MQTT_USE_TLS", False),
            mqtt_client_id=getenv("MQTT_CLIENT_ID", "jarvis-desktop").strip() or "jarvis-desktop",
            mqtt_keepalive=_positive_int("MQTT_KEEPALIVE", 60),
            mqtt_default_qos=_bounded_int("MQTT_DEFAULT_QOS", 1, 0, 2),
            mqtt_reconnect_enabled=_boolean("MQTT_RECONNECT_ENABLED", True),
            mqtt_reconnect_max_seconds=_positive_int("MQTT_RECONNECT_MAX_SECONDS", 30),
            mqtt_topic_prefix=_mqtt_topic_prefix(),
            mqtt_max_payload_bytes=_positive_int("MQTT_MAX_PAYLOAD_BYTES", 16_384),
            iot_telemetry_retention_days=_positive_int("IOT_TELEMETRY_RETENTION_DAYS", 30),
            iot_command_timeout=_positive_int("IOT_COMMAND_TIMEOUT", 5),
            iot_rule_cooldown_seconds=_positive_int("IOT_RULE_COOLDOWN_SECONDS", 60),
            iot_default_device=getenv("IOT_DEFAULT_DEVICE", "").strip(),
            iot_verbose_telemetry_log=_boolean("IOT_VERBOSE_TELEMETRY_LOG", False),
            orchestrator_enabled=_boolean("ORCHESTRATOR_ENABLED", True),
            orchestrator_mode=_orchestrator_mode(),
            orchestrator_max_retries=_bounded_int("ORCHESTRATOR_MAX_RETRIES", 2, 0, 5),
            orchestrator_max_replans=_bounded_int("ORCHESTRATOR_MAX_REPLANS", 2, 0, 5),
            orchestrator_max_parallel_tasks=_bounded_int("ORCHESTRATOR_MAX_PARALLEL_TASKS", 3, 1, 6),
            automation_engine_enabled=_boolean("AUTOMATION_ENGINE_ENABLED", True),
            automation_max_actions=_bounded_int("AUTOMATION_MAX_ACTIONS", 8, 1, 20),
            automation_cooldown_seconds=_positive_int("AUTOMATION_COOLDOWN_SECONDS", 60),
            automation_poll_seconds=_positive_int("AUTOMATION_POLL_SECONDS", 20),
            automation_misfire_policy=_automation_misfire_policy(),
            telegram_enabled=_boolean("TELEGRAM_ENABLED", False),
            telegram_bot_token=getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_chat_id=getenv("TELEGRAM_CHAT_ID", "").strip(),
            telegram_timeout_seconds=_bounded_int("TELEGRAM_TIMEOUT_SECONDS", 3, 1, 20),
            telegram_retry_attempts=_bounded_int("TELEGRAM_RETRY_ATTEMPTS", 1, 0, 3),
            telegram_queue_size=_bounded_int("TELEGRAM_QUEUE_SIZE", 250, 10, 2_000),
            telegram_deduplication_seconds=_bounded_int("TELEGRAM_DEDUPLICATION_SECONDS", 3, 0, 300),
            cyberseg_enabled=_boolean("CYBERSEG_ENABLED", False),
            cyberseg_api_url=_cyberseg_api_url(),
            cyberseg_api_token=getenv("CYBERSEG_API_TOKEN", ""),
            cyberseg_timeout_seconds=_bounded_int("CYBERSEG_TIMEOUT_SECONDS", 3, 1, 15),
            cyberseg_http_retry_attempts=_bounded_int("CYBERSEG_HTTP_RETRY_ATTEMPTS", 2, 0, 5),
            cyberseg_http_retry_backoff_seconds=_bounded_float("CYBERSEG_HTTP_RETRY_BACKOFF_SECONDS", 0.35, 0, 5),
            cyberseg_monitor_enabled=_boolean("CYBERSEG_MONITOR_ENABLED", False),
            cyberseg_monitor_poll_seconds=_bounded_int("CYBERSEG_MONITOR_POLL_SECONDS", 15, 5, 3_600),
            cyberseg_monitor_max_poll_seconds=_bounded_int("CYBERSEG_MONITOR_MAX_POLL_SECONDS", 120, 5, 3_600),
            cyberseg_monitor_retry_attempts=_bounded_int("CYBERSEG_MONITOR_RETRY_ATTEMPTS", 2, 0, 5),
            cyberseg_monitor_failure_threshold=_bounded_int("CYBERSEG_MONITOR_FAILURE_THRESHOLD", 3, 1, 10),
            cyberseg_monitor_min_risk=_cyberseg_monitor_minimum_risk(),
            cyberseg_monitor_clean_report_seconds=_bounded_int("CYBERSEG_MONITOR_CLEAN_REPORT_SECONDS", 86_400, 60, 604_800),
            cyberseg_monitor_notify_existing=_boolean("CYBERSEG_MONITOR_NOTIFY_EXISTING", False),
            cyberseg_monitor_notify_service_state=_boolean("CYBERSEG_MONITOR_NOTIFY_SERVICE_STATE", False),
            cyberseg_deployment_profile=_cyberseg_deployment_profile(),
            cyberseg_server_auto_block=_boolean("CYBERSEG_SERVER_AUTO_BLOCK", False),
            cyberseg_server_firewall=_cyberseg_firewall(),
            cyberseg_server_min_risk=_cyberseg_minimum_risk(),
            cyberseg_server_allowlist=_csv_values("CYBERSEG_SERVER_ALLOWLIST"),
            cyberseg_server_allow_private_sources=_boolean("CYBERSEG_SERVER_ALLOW_PRIVATE_SOURCES", False),
            # The desktop application is the default interface.  The optional
            # local dashboard can still be enabled for integrations or Docker.
            dashboard_enabled=_boolean("DASHBOARD_ENABLED", False),
            dashboard_host=_dashboard_host(),
            dashboard_port=_bounded_int("DASHBOARD_PORT", 8765, 1024, 65535),
            dashboard_auto_open=_boolean("DASHBOARD_AUTO_OPEN", False),
            dashboard_ws_enabled=_boolean("DASHBOARD_WS_ENABLED", True),
            dashboard_system_metrics_interval=_bounded_int("DASHBOARD_SYSTEM_METRICS_INTERVAL", 2, 1, 60),
            dashboard_telemetry_interval=_bounded_int("DASHBOARD_TELEMETRY_INTERVAL", 2, 1, 60),
            mobile_api_enabled=_boolean("MOBILE_API_ENABLED", False),
            mobile_api_token=getenv("MOBILE_API_TOKEN", "").strip(),
            productivity_enabled=_boolean("PRODUCTIVITY_ENABLED", True),
            google_integration_enabled=_boolean("GOOGLE_INTEGRATION_ENABLED", True),
            google_oauth_credentials_file=getenv("GOOGLE_OAUTH_CREDENTIALS_FILE", "data/integrations/google-credentials.json").strip(),
            google_oauth_token_file=getenv("GOOGLE_OAUTH_TOKEN_FILE", "data/integrations/google-token.json").strip(),
            productivity_timezone=getenv("PRODUCTIVITY_TIMEZONE", "America/Guayaquil").strip() or "America/Guayaquil",
            users_enabled=_boolean("USERS_ENABLED", True),
            user_auth_enabled=_boolean("USER_AUTH_ENABLED", True),
            user_default_role=getenv("USER_DEFAULT_ROLE", "standard").strip().lower(),
            user_auto_lock_minutes=_positive_int("USER_AUTO_LOCK_MINUTES", 30),
            user_password_hasher=getenv("USER_PASSWORD_HASHER", "bcrypt").strip().lower(),
            multiuser_memory_isolation=_boolean("MULTIUSER_MEMORY_ISOLATION", True),
            multiuser_browser_profile_isolation=_boolean("MULTIUSER_BROWSER_PROFILE_ISOLATION", True),
            hud_enabled=_boolean("HUD_ENABLED", True),
            hud_mode=getenv("HUD_MODE", "hud").strip().lower() if getenv("HUD_MODE", "hud").strip().lower() in {"dashboard", "hud", "overlay", "minimal"} else "hud",
            hud_particles=_boolean("HUD_PARTICLES", True),
            hud_target_fps=_bounded_int("HUD_TARGET_FPS", 60, 20, 60),
            hud_audio_visualizer=_boolean("HUD_AUDIO_VISUALIZER", True),
            hud_agent_graph=_boolean("HUD_AGENT_GRAPH", True),
            hud_system_metrics=_boolean("HUD_SYSTEM_METRICS", True),
            hud_auto_hide_conversation=_boolean("HUD_AUTO_HIDE_CONVERSATION", True),
            desktop_overlay_enabled=_boolean("DESKTOP_OVERLAY_ENABLED", False),
            system_tray_enabled=_boolean("SYSTEM_TRAY_ENABLED", False),
            wake_sound_enabled=_boolean("WAKE_SOUND_ENABLED", True),
            startup_sound_enabled=_boolean("STARTUP_SOUND_ENABLED", False),
        )
