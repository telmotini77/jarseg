from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from app.automation.action import Action
from app.automation.routines.manager import RoutineManager
from app.automation.routines.repository import RoutineRepository
from app.commands.base import Command, CommandResult
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.memory.context_builder import build_memory_context
from app.memory.manager import MemoryManager
from app.memory.models import MemoryPolicy
from app.memory.repository import MemoryRepository
from app.memory.sensitive_filter import sanitize_for_storage
from app.tasks.manager import ReminderManager
from app.tasks.models import TaskStatus
from app.tasks.parser import parse_schedule
from app.tasks.repository import TaskRepository
from app.tasks.scheduler import LocalScheduler
from app.wakeword.detector import WakeWordDetector
from app.wakeword.provider import TranscriptWakeWordProvider


def build_memory(tmp_path: Path) -> tuple[MemoryRepository, MemoryManager]:
    repository = MemoryRepository(tmp_path / "jarvis.db")
    return repository, MemoryManager(repository, MemoryPolicy.EXPLICIT_ONLY, max_results=5)


def test_memory_persists_ranks_updates_and_deletes(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path)
    stored = memory.remember("Mi editor principal es Visual Studio Code.")
    assert stored is not None
    reopened = MemoryManager(MemoryRepository(tmp_path / "jarvis.db"), max_results=5)
    matches = reopened.recall("cuál es mi editor principal")
    assert matches and matches[0].content == stored.content
    updated = repository.update_memory(stored.id, "Mi editor principal es VS Code.")
    assert updated is not None and "VS Code" in updated.content
    forgotten = reopened.forget("editor principal")
    assert forgotten.deleted is not None
    assert repository.get_memory(stored.id) is None


def test_memory_filter_context_and_persistent_conversation(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path)
    sanitized = sanitize_for_storage("Mi API key: sk-abcdefghijklmnopqrstuv")
    assert sanitized.redacted and "[REDACTED_SECRET]" in sanitized.content
    preference = memory.remember("Prefiero respuestas cortas.")
    assert preference is not None and preference.memory_type == "preference" and preference.key == "response_style"
    assert "respuestas cortas" in build_memory_context(memory.recall("preferencias"))

    conversation = ConversationManager(repository=repository)
    conversation.add_user_message("token=ghp_abcdefghijklmnopqrstuvwx")
    assert conversation._conversation_id is not None
    stored_messages = repository.list_messages(conversation._conversation_id)
    assert stored_messages and "[REDACTED_SECRET]" in stored_messages[0].content
    conversation.close()


def test_reminder_parser_scheduler_and_persistence_without_real_waits(tmp_path: Path) -> None:
    zone = ZoneInfo("America/Guayaquil")
    now = datetime(2026, 8, 25, 9, 0, tzinfo=zone)
    parsed = parse_schedule("mañana a las 8", now, "America/Guayaquil")
    assert parsed.trigger_at == datetime(2026, 8, 26, 8, 0, tzinfo=zone)
    assert parse_schedule("cada lunes a las 8", now, "America/Guayaquil").recurrence == "weekly:0"

    manager = ReminderManager(TaskRepository(tmp_path / "jarvis.db"), "America/Guayaquil")
    reminder = manager.create_from_text("revisar Docker en 20 minutos", now)
    assert reminder.status is TaskStatus.PENDING
    fired: list[str] = []
    scheduler = LocalScheduler(manager, lambda item: fired.append(item.title), poll_seconds=0.01)
    assert scheduler.run_pending(now + timedelta(minutes=19)) == []
    scheduler.run_pending(now + timedelta(minutes=20))
    scheduler.run_pending(now + timedelta(minutes=21))
    assert fired == ["revisar Docker"]
    assert not manager.list_pending()


def test_reminder_cancellation_and_recurring_reschedule(tmp_path: Path) -> None:
    zone = ZoneInfo("America/Guayaquil")
    now = datetime(2026, 8, 25, 9, 0, tzinfo=zone)
    manager = ReminderManager(TaskRepository(tmp_path / "jarvis.db"), "America/Guayaquil")
    daily = manager.repository.create("tomar un descanso", now - timedelta(minutes=1), "daily")
    due = manager.due(now)
    assert due == [daily]
    manager.mark_triggered(daily)
    pending = manager.list_pending()
    assert pending and pending[0].trigger_at.date() == (now + timedelta(days=1)).date()
    cancelled, _matches = manager.cancel("descanso")
    assert cancelled is not None
    assert not manager.list_pending()


class FakeApps:
    def __init__(self) -> None:
        self.events: list[str] = []

    def open(self, target: str | None) -> CommandResult:
        self.events.append(f"open:{target}")
        return CommandResult(True, f"Abriendo {target}.")

    def close(self, target: str | None) -> CommandResult:
        return CommandResult(True, "cerrado")


def test_router_memory_reminders_and_safe_routine(tmp_path: Path) -> None:
    repository, memory = build_memory(tmp_path)
    reminders = ReminderManager(TaskRepository(repository.path), "America/Guayaquil")
    routines = RoutineManager(RoutineRepository(repository.path))
    apps = FakeApps()
    router = CommandRouter(applications=apps, memory=memory, reminders=reminders, routines=routines)

    command = router.parse("Jarvis recuerda que mis proyectos están en Documentos")
    assert command is not None and command.action == "memory_remember"
    assert router.execute(command).success
    recall = router.parse("Jarvis ¿dónde guardo mis proyectos?")
    assert recall is not None and "Documentos" in router.execute(recall).message
    reminder = router.parse("Jarvis recuérdame revisar GitHub en 20 minutos")
    assert reminder is not None and reminder.action == "reminder_create"
    assert router.execute(reminder).success

    routines.create("modo programación", [Action("open_application", "vscode")])
    result = router.execute(Command("routine_execute", target="modo programación"))
    assert result.success and apps.events == ["open:vscode"]
    with pytest.raises(ValueError):
        routines.create("insegura", [Action("run_powershell", "rm -rf")])


class FakeMicrophone:
    def __init__(self) -> None:
        self.calls = 0

    def listen(self, timeout: int, phrase_time_limit: int) -> object:
        self.calls += 1
        return object()


class FakeStt:
    def __init__(self, messages: list[str]) -> None:
        self._messages = messages

    def transcribe(self, audio: object) -> str:
        return self._messages.pop(0)


def test_wake_word_detects_command_timeout_path_and_suspension() -> None:
    provider = TranscriptWakeWordProvider(FakeMicrophone(), FakeStt(["Jarvis abre Chrome"]), 8, 20)
    detector = WakeWordDetector(provider, 8)
    assert detector.wait_for_command() == "Jarvis abre Chrome"

    standalone = TranscriptWakeWordProvider(FakeMicrophone(), FakeStt(["Jarvis", "qué hora es"]), 8, 20)
    assert standalone.wait_for_wake_word()
    assert standalone.capture_command(8) == "Jarvis qué hora es"
    standalone.suspend()
    assert not standalone.wait_for_wake_word()
    standalone.resume()
