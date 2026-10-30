from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import threading
import webbrowser
from pathlib import Path

from app.ai.provider import AIProviderError, create_ai_provider
from app.commands.apps import ApplicationService
from app.commands.browser import BrowserService
from app.commands.router import CommandRouter
from app.code.agent import CodeAgent
from app.code.project_builder import ProjectBuilder
from app.code.models import CodeAgentMode
from app.code.project import ProjectInspector
from app.code.scanner import ProjectScanner, ScanLimits
from app.iot.agent import IoTAgent
from app.iot.mqtt_provider import MQTTProviderConfig, PahoMQTTProvider
from app.iot.repository import IoTRepository
from app.core.config import ConfigurationError, Settings
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis
from app.input.keyboard import KeyboardController
from app.input.mouse import MouseController
from app.input.headless import HeadlessDesktopBackend
from app.memory.manager import MemoryManager
from app.memory.encryption import MemoryCipher
from app.memory.models import MemoryPolicy
from app.memory.repository import MemoryRepository
from app.system.window_manager import WindowManager
from app.tasks.manager import ReminderManager
from app.tasks.repository import TaskRepository
from app.tasks.scheduler import LocalScheduler
from app.utils.logger import configure_logging
from app.vision.analyzer import ContextVisionProvider, OpenAIVisionProvider, VisionProviderError
from app.vision.screenshot import ScreenshotService
from app.vision.service import VisionService
from app.voice.microphone import Microphone, MicrophoneError
from app.voice.speech_to_text import GoogleSpeechRecognitionProvider, SpeechToTextError
from app.voice.text_to_speech import PiperTTSProvider, Pyttsx3Provider, TextToSpeechError
from app.wakeword.detector import WakeWordDetector
from app.wakeword.provider import TranscriptWakeWordProvider
from app.automation.routines.manager import RoutineManager
from app.automation.routines.repository import RoutineRepository
from app.automation_engine.engine import AutomationEngine
from app.automation_engine.repository import AutomationRepository
from app.automation_engine.scheduler import AutomationScheduler
from app.agents import (
    AgentRegistry, AutomationAgent, BrowserAgent, CodeSpecialistAgent, ConversationAgent,
    IoTSpecialistAgent, MemoryAgent, SystemAgent, TerminalAgent as OrchestratedTerminalAgent, VisionAgent,
    ProductivitySpecialistAgent, CyberSegAgent,
)
from app.browser.browser_manager import BrowserManager
from app.browser.playwright_provider import PlaywrightProvider
from app.terminal.executor import SubprocessTerminalProvider
from app.terminal.history import TerminalHistory
from app.terminal.manager import TerminalManager
from app.terminal.models import TerminalMode
from app.terminal.working_directory import WorkingDirectoryManager
from app.events.bus import EventBus
from app.orchestrator.models import OrchestratorMode
from app.orchestrator.orchestrator import JarvisOrchestrator
from app.api.dependencies import DashboardContext
from app.api.server import DashboardServer
from app.productivity.agent import ProductivityAgent
from app.productivity.google_provider import GoogleWorkspaceProvider
from app.users.manager import UserManager
from app.experience.service import ExperienceService
from app.experience.states import JarvisVisualState
from app.notifications import TelegramNotifier
from app.cyberseg import CyberSegClient, CyberSegMonitor, LinuxFirewallBlocker, ServerIntrusionResponder


def print_header() -> None:
    print("=" * 40)
    print("             JARVIS v1.4")
    print("           USER PROFILES")
    print("=" * 40)
    print("\nInicializando...\n")


def configure_console_encoding() -> None:
    """Keep Unicode status messages from crashing legacy Windows consoles."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


def say(
    tts: Pyttsx3Provider,
    text: str,
    logger: logging.Logger,
    enabled: bool = True,
    wake_word: WakeWordDetector | None = None,
) -> None:
    print(f"\nJARVIS:\n{text}")
    if not enabled:
        return
    try:
        if wake_word is not None:
            wake_word.suspend()
        tts.speak(text)
    except TextToSpeechError as error:
        logger.exception("TTS error")
        print(f"[Aviso] {error}")
    finally:
        if wake_word is not None:
            wake_word.resume()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="JARVIS v1.4 — Aplicación de escritorio")
    parser.add_argument("--console", action="store_true", help="Ejecuta JARVIS sin el panel gráfico.")
    parser.add_argument("--desktop", action="store_true", help="Inicia el HUD nativo de escritorio (comportamiento predeterminado).")
    parser.add_argument("--legacy-panel", action="store_true", help="Usa el panel clásico de JARVIS en lugar del HUD nativo.")
    parser.add_argument("--dashboard", action="store_true", help="Habilita además el dashboard web local, sin abrir un navegador automáticamente.")
    parser.add_argument("--service", action="store_true", help="Ejecuta JARVIS como servicio en segundo plano, sin micrófono ni HUD.")
    parser.add_argument("--server", action="store_true", help="Ejecuta el perfil de servidor Linux: servicio sin interfaz y respuesta defensiva configurada.")
    return parser.parse_args()


def main() -> int:
    configure_console_encoding()
    arguments = parse_args()
    logger = configure_logging()
    print_header()
    dashboard_server: DashboardServer | None = None
    telegram: TelegramNotifier | None = None
    cyberseg_monitor: CyberSegMonitor | None = None
    try:
        settings = Settings.from_env()
        service_mode = arguments.service or arguments.server or settings.cyberseg_deployment_profile == "server"
        cyberseg_profile = "server" if arguments.server else settings.cyberseg_deployment_profile
        print("[OK] Configuración")
        cipher = MemoryCipher(settings.memory_encryption_enabled, settings.memory_encryption_key or None)
        database = MemoryRepository(settings.memory_database, cipher=cipher)
        print("[OK] Base de datos")
        memory = MemoryManager(
            database,
            policy=MemoryPolicy(settings.memory_mode if settings.memory_enabled else "disabled"),
            max_results=settings.memory_max_results,
            logger=logger,
            context_max_items=settings.memory_context_max_items,
            context_max_tokens=settings.memory_context_max_tokens,
        )
        print("[OK] Memory Engine 2.0 (vectores locales)")
        users = UserManager(settings.memory_database, memory, auth_enabled=settings.user_auth_enabled) if settings.users_enabled else None
        print("[OK] User Manager" if users else "[OK] User Profiles desactivados")
        print("[OK] Session Manager" if users else "")
        print("[OK] Permission Manager" if users else "")
        if users and users.active_user():
            print(f"Active Profile: {users.active_user().display_name}")
            print("JARVIS: Perfil cargado correctamente.")
        event_bus = EventBus(logger)
        experience = ExperienceService(event_bus, enabled=settings.hud_enabled, mode=settings.hud_mode)
        experience.set_state(JarvisVisualState.IDLE)
        telegram = TelegramNotifier(
            token=settings.telegram_bot_token,
            chat_id=settings.telegram_chat_id,
            enabled=settings.telegram_enabled,
            timeout_seconds=settings.telegram_timeout_seconds,
            retry_attempts=settings.telegram_retry_attempts,
            queue_size=settings.telegram_queue_size,
            deduplication_seconds=settings.telegram_deduplication_seconds,
            logger=logger,
        )
        telegram.start()
        print("[OK] Event Bus central")
        print("[OK] Telegram alerts" if telegram.enabled else "[OK] Telegram alerts desactivadas")
        reminders = ReminderManager(TaskRepository(settings.memory_database), settings.timezone, logger)
        routines = RoutineManager(RoutineRepository(settings.memory_database), logger)
        scheduler: LocalScheduler | None = None
        if settings.wake_word_enabled and not service_mode:
            microphone = Microphone(settings.microphone_index, settings.ambient_noise_duration)
            try:
                microphone.validate()
                print("[OK] Micrófono")
                stt = GoogleSpeechRecognitionProvider(settings.stt_language)
                print("[OK] Speech-to-Text")
                wake_word = WakeWordDetector(
                    TranscriptWakeWordProvider(
                        microphone, stt, settings.listen_timeout, settings.phrase_time_limit, settings.wake_word
                    ),
                    settings.wake_command_timeout,
                    logger,
                )
            except Exception as error:
                logger.warning(f"No se pudo inicializar la entrada de audio: {error}. Wake word desactivado.")
                microphone = None
                stt = None
                wake_word = None
                print("[Aviso] Wake Word desactivado por falta de micrófono/audio.")
        else:
            microphone = None
            stt = None
            wake_word = None
            print("[OK] Wake Word desactivado")
        provider = create_ai_provider(settings)
        print("[OK] Inteligencia Artificial")
        if settings.tts_enabled and not service_mode:
            try:
                if settings.tts_provider == "piper":
                    tts = PiperTTSProvider(Path(settings.tts_piper_model_dir), settings.tts_volume)
                    print("[OK] Text-to-Speech (voz neuronal DaveFX)")
                else:
                    tts = Pyttsx3Provider(settings.tts_rate, settings.tts_voice_hint, settings.tts_volume)
                    print("[OK] Text-to-Speech (voz de Windows)")
            except Exception as error:
                logger.warning(f"No se pudo inicializar Text-to-Speech ({error}). Usando fallback silencioso.")
                from app.voice.text_to_speech import TextToSpeechProvider
                class DummyTTSProvider(TextToSpeechProvider):
                    def speak(self, text: str) -> None: pass
                    def close(self) -> None: pass
                tts = DummyTTSProvider()
        else:
            from app.voice.text_to_speech import TextToSpeechProvider
            class DummyTTSProvider(TextToSpeechProvider):
                def speak(self, text: str) -> None: pass
                def close(self) -> None: pass
            tts = DummyTTSProvider()
            print("[OK] Text-to-Speech desactivado")

        def deliver_alert(message: str) -> None:
            """Queue Telegram first; voice feedback must never delay an alert."""
            telegram.notify(message)
            threading.Thread(
                target=say,
                args=(tts, message, logger, settings.tts_enabled and not service_mode, wake_word),
                daemon=True,
                name="jarvis-alert-voice",
            ).start()

        browser_agent = BrowserManager(
            PlaywrightProvider(
                Path(settings.browser_profile_dir),
                headless=settings.browser_headless,
                timeout_ms=settings.browser_timeout * 1_000,
                channel=settings.browser_channel,
            ),
            search_engine=settings.browser_default_search_engine,
            answerer=provider.generate_response,
            logger=logger,
            memory=memory,
        )
        print("[OK] Survivor (Chrome + Playwright)")
        terminal_agent = TerminalManager(
            SubprocessTerminalProvider(settings.terminal_max_output),
            WorkingDirectoryManager(Path.cwd()),
            timeout=settings.terminal_default_timeout,
            enabled=settings.terminal_enabled,
            mode=TerminalMode(settings.terminal_mode),
            allow_powershell=settings.terminal_allow_powershell,
            allow_cmd=settings.terminal_allow_cmd,
            managed_processes_enabled=settings.terminal_managed_processes,
            history=TerminalHistory(Path(settings.memory_database).parent / "terminal_history.jsonl"),
            answerer=provider.generate_response,
            logger=logger,
            memory=memory,
        )
        print("[OK] Terminal Agent")
        print("[OK] Command Validator")
        print("[OK] Process Manager")
        code_agent = CodeAgent(
            terminal_agent,
            memory,
            mode=CodeAgentMode(settings.code_agent_mode),
            inspector=ProjectInspector(ProjectScanner(ScanLimits(
                max_files=settings.code_max_files,
                max_file_size=settings.code_max_file_size,
                max_total_bytes=settings.code_max_total_bytes,
                respect_gitignore=settings.code_respect_gitignore,
            ))),
            vscode_enabled=settings.vscode_integration_enabled,
            max_fix_attempts=settings.code_max_fix_attempts,
            max_context_tokens=settings.code_max_context_tokens,
            auto_run_tests=settings.code_auto_run_tests,
            auto_run_lint=settings.code_auto_run_lint,
            project_builder=ProjectBuilder(
                Path(settings.project_builder_root),
                provider.generate_response,
                max_files=settings.project_builder_max_files,
                max_file_chars=settings.project_builder_max_file_chars,
            ) if settings.project_builder_enabled else None,
        ) if settings.code_agent_enabled else None
        print("[OK] Code Agent" if code_agent else "[OK] Code Agent desactivado")
        print("[OK] Project Builder" if code_agent and settings.project_builder_enabled else "[OK] Project Builder desactivado")
        if code_agent:
            print("[OK] Project Scanner")
            print("[OK] Code Search")
            print("[OK] Patch Engine")
            print("[OK] Test Runner")
            print("[OK] VS Code Integration" if settings.vscode_integration_enabled else "[OK] VS Code Integration desactivada")
        iot_agent = None
        if settings.iot_enabled:
            iot_repository = IoTRepository(settings.memory_database)

            def announce_iot(message: str) -> None:
                logger.info("IOT alert delivered")
                deliver_alert(message)

            iot_agent = IoTAgent(
                PahoMQTTProvider(MQTTProviderConfig(
                    host=settings.mqtt_broker_host,
                    port=settings.mqtt_broker_port,
                    client_id=settings.mqtt_client_id,
                    username=settings.mqtt_username,
                    password=settings.mqtt_password,
                    use_tls=settings.mqtt_use_tls,
                    keepalive=settings.mqtt_keepalive,
                    reconnect_max_seconds=settings.mqtt_reconnect_max_seconds,
                    reconnect_enabled=settings.mqtt_reconnect_enabled,
                )),
                iot_repository,
                memory=memory,
                topic_prefix=settings.mqtt_topic_prefix,
                default_device=settings.iot_default_device or None,
                default_qos=settings.mqtt_default_qos,
                telemetry_retention_days=settings.iot_telemetry_retention_days,
                max_payload_bytes=settings.mqtt_max_payload_bytes,
                command_timeout=settings.iot_command_timeout,
                rule_cooldown_seconds=settings.iot_rule_cooldown_seconds,
                logger=logger,
                alert_callback=announce_iot,
                verbose_telemetry_log=settings.iot_verbose_telemetry_log,
                reconnect_enabled=settings.mqtt_reconnect_enabled,
                central_events=event_bus,
            )
            print("[OK] MQTT Provider")
            print("[OK] Device Registry")
            print("[OK] Telemetry Manager")
            print("[OK] Command Manager")
            print("[OK] Rule Engine")
            print("[MQTT] Desconectado (di 'Jarvis conecta MQTT')")
            print("[IoT] Dispositivos online: 0")
        else:
            print("[OK] IoT Agent desactivado")

        def announce_reminder(reminder) -> None:
            deliver_alert(f"Recordatorio: es hora de {reminder.title}.")

        scheduler = LocalScheduler(reminders, announce_reminder, logger=logger)
        print("[OK] Scheduler")
        windows = WindowManager()
        print("[OK] Window Manager")
        if service_mode:
            desktop_backend = HeadlessDesktopBackend()
            mouse = MouseController(backend=desktop_backend)
            keyboard = KeyboardController(backend=desktop_backend)
            print("[OK] Controles de escritorio aislados para el servicio")
        else:
            mouse = MouseController()
            print("[OK] Mouse Controller")
            keyboard = KeyboardController()
            print("[OK] Keyboard Controller")
        vision_provider = (
            OpenAIVisionProvider(settings.openai_api_key, settings.openai_model)
            if settings.ai_provider == "openai"
            else ContextVisionProvider()
        )
        vision = VisionService(
            screenshots=ScreenshotService(windows),
            windows=windows,
            mouse=mouse,
            provider=vision_provider,
        )
        print("[OK] Screen Capture")
        print("[OK] Vision")
        applications = ApplicationService(settings.chrome_profile)
        cyberseg_client = CyberSegClient(
            settings.cyberseg_api_url,
            settings.cyberseg_api_token,
            settings.cyberseg_timeout_seconds,
            settings.cyberseg_http_retry_attempts,
            settings.cyberseg_http_retry_backoff_seconds,
        ) if settings.cyberseg_enabled else None
        print("[OK] CyberSeg local conectado" if cyberseg_client else "[OK] CyberSeg desactivado")
        response_handler = None
        if cyberseg_profile == "server" and settings.cyberseg_server_auto_block:
            responder = ServerIntrusionResponder(
                LinuxFirewallBlocker(settings.cyberseg_server_firewall),
                minimum_risk=settings.cyberseg_server_min_risk,
                allowlist=settings.cyberseg_server_allowlist,
                allow_private_sources=settings.cyberseg_server_allow_private_sources,
                logger=logger,
            )
            response_handler = responder.handle
            print("[OK] Respuesta defensiva de servidor activada")
        elif cyberseg_profile == "server":
            print("[OK] Perfil servidor: bloqueo automático desactivado")
        if cyberseg_client is not None and settings.cyberseg_monitor_enabled:
            cyberseg_monitor = CyberSegMonitor(
                cyberseg_client,
                deliver_alert,
                poll_seconds=settings.cyberseg_monitor_poll_seconds,
                max_poll_seconds=settings.cyberseg_monitor_max_poll_seconds,
                retry_attempts=settings.cyberseg_monitor_retry_attempts,
                failure_threshold=settings.cyberseg_monitor_failure_threshold,
                minimum_risk=settings.cyberseg_monitor_min_risk,
                clean_report_seconds=settings.cyberseg_monitor_clean_report_seconds,
                notify_existing=settings.cyberseg_monitor_notify_existing,
                notify_service_state=settings.cyberseg_monitor_notify_service_state,
                alert_handler=response_handler,
                logger=logger,
            )
            cyberseg_monitor.start()
            print("[OK] Monitor CyberSeg en segundo plano")

        def open_project(path: Path):
            if code_agent is None:
                from app.commands.base import CommandResult
                return CommandResult(False, "Code Agent no está disponible para abrir el proyecto.")
            code_agent.analyze_project(path)
            return code_agent.open_vscode()

        def run_project_tests(path: Path) -> str:
            if code_agent is None:
                return "Code Agent no está disponible para ejecutar tests."
            code_agent.analyze_project(path)
            return code_agent.run_tests()

        agent_registry = AgentRegistry()
        automation_adapter = AutomationAgent(None)
        google_productivity_provider = GoogleWorkspaceProvider(settings.google_oauth_credentials_file, settings.google_oauth_token_file) if settings.productivity_enabled and settings.google_integration_enabled else None
        productivity = ProductivityAgent(google_productivity_provider, google_productivity_provider, settings.productivity_timezone) if settings.productivity_enabled else None
        for agent in (
            ConversationAgent(), MemoryAgent(memory), SystemAgent(applications, open_project),
            BrowserAgent(browser_agent), OrchestratedTerminalAgent(terminal_agent, run_project_tests),
            CodeSpecialistAgent(code_agent), IoTSpecialistAgent(iot_agent), VisionAgent(vision), automation_adapter,
            ProductivitySpecialistAgent(productivity), CyberSegAgent(cyberseg_client),
        ):
            agent_registry.register(agent)
        automation_engine = None
        automation_scheduler = None
        if settings.automation_engine_enabled:
            automation_engine = AutomationEngine(
                AutomationRepository(settings.memory_database), agent_registry, event_bus,
                max_actions=settings.automation_max_actions, cooldown_seconds=settings.automation_cooldown_seconds,
                notifier=deliver_alert, logger=logger,
            )
            automation_adapter.engine = automation_engine
            automation_scheduler = AutomationScheduler(automation_engine, settings.automation_poll_seconds, logger)
            print("[OK] Automation Engine")
        else:
            print("[OK] Automation Engine desactivado")
        orchestrator = None
        if settings.orchestrator_enabled:
            orchestrator = JarvisOrchestrator(
                agent_registry, event_bus, memory=memory, mode=OrchestratorMode(settings.orchestrator_mode),
                max_retries=settings.orchestrator_max_retries, max_parallel_tasks=settings.orchestrator_max_parallel_tasks,
                max_replans=settings.orchestrator_max_replans, logger=logger,
            )
            print("[OK] Multi-Agent Orchestrator")
        else:
            print("[OK] Multi-Agent Orchestrator desactivado")
        print("[OK] Productivity Agent" if productivity else "[OK] Productivity Agent desactivado")
        router = CommandRouter(
            applications=applications,
            browser=BrowserService(settings.chrome_profile),
            windows=windows,
            mouse=mouse,
            keyboard=keyboard,
            vision=vision,
            memory=memory,
            reminders=reminders,
            routines=routines,
            browser_agent=browser_agent,
            terminal_agent=terminal_agent,
            code_agent=code_agent,
            iot_agent=iot_agent,
            cyberseg_client=cyberseg_client,
            orchestrator=orchestrator,
            agent_registry=agent_registry,
            automation_engine=automation_engine,
            user_manager=users,
        )
        print("[OK] Command Router")
        print("[OK] Security Manager")
        print(f"[Terminal] Modo {settings.terminal_mode.upper()}")
    except (ConfigurationError, MicrophoneError, AIProviderError, TextToSpeechError, VisionProviderError, ImportError, sqlite3.Error) as error:
        if cyberseg_monitor is not None:
            cyberseg_monitor.stop()
        if telegram is not None:
            telegram.stop()
        logger.exception("Startup failed")
        print(f"[ERROR] No se pudo iniciar JARVIS: {error}")
        return 1

    jarvis = Jarvis(provider, ConversationManager(settings.max_conversation_turns, database), router, logger, memory=memory, user_manager=users, experience=experience)
    if settings.dashboard_enabled or arguments.dashboard or service_mode:
        dashboard_server = DashboardServer(
            DashboardContext(
                jarvis=jarvis, events=event_bus, agents=agent_registry, orchestrator=orchestrator,
                automations=automation_engine, terminal=terminal_agent, code=code_agent, browser=browser_agent,
                iot=iot_agent, memory=memory, microphone=microphone, wake_word=wake_word, settings=settings,
                productivity=productivity,
                users=users,
                experience=experience,
                cyberseg=cyberseg_client,
            ),
            settings.dashboard_host, settings.dashboard_port, Path(__file__).parent / "dashboard" / "dist", logger,
        )
        dashboard_server.start()
        dashboard_url = f"http://{settings.dashboard_host}:{settings.dashboard_port}"
        print("[OK] API Server")
        print("[OK] WebSocket Gateway" if settings.dashboard_ws_enabled else "[OK] WebSocket Gateway desactivado")
        print("[OK] Dashboard")
        print(f"\nDashboard:\n{dashboard_url}\n")
        # The native desktop app is the primary experience.  A browser is an
        # explicit opt-in, even when the local API was enabled for integrations.
        if arguments.dashboard and settings.dashboard_auto_open:
            try:
                webbrowser.open(dashboard_url, new=2)
            except OSError:
                logger.warning("Dashboard browser open skipped")
    logger.info("JARVIS started")
    if not arguments.console and not service_mode:
        try:
            if arguments.legacy_panel:
                from app.ui.panel import JarvisPanel

                panel = JarvisPanel(
                    jarvis=jarvis,
                    microphone=microphone,
                    stt=stt,
                    tts=tts,
                    logger=logger,
                    listen_timeout=settings.listen_timeout,
                    phrase_time_limit=settings.phrase_time_limit,
                    tts_enabled=settings.tts_enabled,
                    wake_word=wake_word,
                    scheduler=scheduler if settings.scheduler_enabled else None,
                )
                interface_name = "Panel clásico"
            else:
                from app.desktop import JarvisDesktopApp

                panel = JarvisDesktopApp(
                    jarvis=jarvis,
                    agents=agent_registry,
                    experience=experience,
                    users=users,
                    microphone=microphone,
                    stt=stt,
                    tts=tts,
                    logger=logger,
                    listen_timeout=settings.listen_timeout,
                    phrase_time_limit=settings.phrase_time_limit,
                    tts_enabled=settings.tts_enabled,
                    wake_word=wake_word,
                    scheduler=scheduler if settings.scheduler_enabled else None,
                    cyberseg=cyberseg_client,
                    particles_enabled=settings.hud_particles,
                    target_fps=settings.hud_target_fps,
                )
                interface_name = "Aplicación de escritorio nativa"
            if automation_scheduler is not None:
                automation_scheduler.start()
            print(f"[OK] {interface_name}")
            panel.run()
        except Exception as error:
            logger.exception("Panel error")
            print(f"[ERROR] El panel visual no pudo iniciarse: {error}")
            return 1
        finally:
            if scheduler is not None:
                scheduler.stop()
            if automation_scheduler is not None:
                automation_scheduler.stop()
            if cyberseg_monitor is not None:
                cyberseg_monitor.stop()
            telegram.stop()
            if dashboard_server is not None:
                dashboard_server.stop()
            if iot_agent is not None:
                iot_agent.disconnect()
            browser_agent.stop()
            jarvis.shutdown()
            tts.close()
            logger.info("JARVIS stopped")
        return 0

    if settings.scheduler_enabled and scheduler is not None:
        scheduler.start()
    if automation_scheduler is not None:
        automation_scheduler.start()
    if service_mode:
        print("[OK] Servicio JARVIS activo en segundo plano")
    else:
        say(tts, "Sistema operativo. Todos los módulos están disponibles.", logger, settings.tts_enabled, wake_word)
    try:
        while True:
            if microphone is None:
                import time
                time.sleep(1)
                continue
            try:
                if wake_word is not None:
                    print('\n[IDLE] Esperando "Jarvis"...')
                    text = wake_word.wait_for_command()
                    if text is None:
                        continue
                    print("👂 Jarvis\n🎤 Te escucho...")
                else:
                    print("\n🎤 Escuchando...")
                    audio = microphone.listen(settings.listen_timeout, settings.phrase_time_limit)
                    if audio is None:
                        print("[Aviso] No se detectó voz. Continúo escuchando.")
                        continue
                    text = stt.transcribe(audio)
            except (MicrophoneError, SpeechToTextError) as error:
                logger.warning("Voice input error: %s", error)
                print(f"[Aviso] {error}")
                continue
            print(f"\nUsuario:\n{text}\n\nProcesando...")
            result = jarvis.process(text)
            say(tts, result.response, logger, settings.tts_enabled, wake_word)
            if result.should_exit:
                break
    except KeyboardInterrupt:
        print("\nInterrupción recibida. Cerrando JARVIS...")
        logger.info("Keyboard interrupt received")
    finally:
        if scheduler is not None:
            scheduler.stop()
        if automation_scheduler is not None:
            automation_scheduler.stop()
        if cyberseg_monitor is not None:
            cyberseg_monitor.stop()
        telegram.stop()
        if dashboard_server is not None:
            dashboard_server.stop()
        if iot_agent is not None:
            iot_agent.disconnect()
        browser_agent.stop()
        jarvis.shutdown()
        tts.close()
        logger.info("JARVIS stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
