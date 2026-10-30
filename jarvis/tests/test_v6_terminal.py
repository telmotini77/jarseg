from __future__ import annotations

import sys
import time
import logging
from pathlib import Path

import pytest

from app.commands.base import Command, RouteType
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis
from app.security.permissions import PermissionManager, SecurityLevel
from app.terminal.context import TerminalContextInspector
from app.terminal.environment import EnvironmentInspector
from app.terminal.executor import SubprocessTerminalProvider
from app.terminal.git.parser import parse_porcelain_status
from app.terminal.history import TerminalHistory
from app.terminal.manager import TerminalManager
from app.terminal.models import CommandSource, TerminalCommand, TerminalCommandResult, TerminalMode
from app.terminal.parser import TerminalParser, package_scripts
from app.terminal.process_manager import ProcessManager
from app.terminal.provider import TerminalProvider
from app.terminal.result_analyzer import summarize_result
from app.terminal.security import display_command, redact_text
from app.terminal.validator import TerminalValidator
from app.terminal.working_directory import WorkingDirectoryManager


class FakeTerminalProvider(TerminalProvider):
    def __init__(self, results: list[TerminalCommandResult] | None = None) -> None:
        self.commands: list[tuple[list[str], Path | None, float | None]] = []
        self.results = results or []

    def execute(self, command: list[str], cwd: Path | None = None, timeout: float | None = None) -> TerminalCommandResult:
        self.commands.append((command, cwd, timeout))
        if self.results:
            return self.results.pop(0)
        return TerminalCommandResult("test", 0, "ok\n", "", 0.02, False, True)


def terminal_result(success: bool = True, stdout: str = "ok\n", stderr: str = "", exit_code: int | None = None) -> TerminalCommandResult:
    return TerminalCommandResult("result", 0 if success else (exit_code or 1), stdout, stderr, 0.02, False, success)


def make_manager(tmp_path: Path, provider: TerminalProvider | None = None) -> TerminalManager:
    return TerminalManager(provider or FakeTerminalProvider(), WorkingDirectoryManager(tmp_path), history=TerminalHistory(), managed_processes_enabled=False)


def test_terminal_command_model_and_redaction() -> None:
    command = TerminalCommand("npm", ("install", "--token", "super-secret"), Path.cwd(), SecurityLevel.CONFIRMATION, True)
    assert command.argv[:2] == ["npm", "install"]
    assert "super-secret" not in display_command(command)
    assert "[REDACTED]" in redact_text("DATABASE_URL=postgres://secret")


@pytest.mark.parametrize(
    ("executable", "args"),
    [
        ("format", ("C:",)),
        ("diskpart", ()),
        ("Remove-Item", ("-Recurse", "-Force", "C:\\")),
        ("git", ("status", "&&", "whoami")),
        ("git", ("reset", "--hard")),
    ],
)
def test_validator_blocks_destructive_and_chained_commands(executable: str, args: tuple[str, ...], tmp_path: Path) -> None:
    checked = TerminalValidator().validate(TerminalCommand(executable, args, tmp_path, source=CommandSource.USER))
    assert not checked.allowed
    assert checked.level in {SecurityLevel.BLOCKED, SecurityLevel.RESTRICTED}


def test_validator_blocks_web_and_model_command_sources(tmp_path: Path) -> None:
    validator = TerminalValidator()
    for source in (CommandSource.WEB_CONTENT, CommandSource.MODEL):
        checked = validator.validate(TerminalCommand("git", ("status",), tmp_path, source=source))
        assert checked.level is SecurityLevel.BLOCKED
        assert "webs o del modelo" in (checked.message or "")


def test_terminal_intent_blocks_plain_destructive_language(tmp_path: Path) -> None:
    router = CommandRouter(terminal_agent=make_manager(tmp_path))
    route = router.route("Jarvis formatea el disco C")
    assert route.type is RouteType.TERMINAL_COMMAND
    assert route.parsed_command is not None
    decision = PermissionManager().evaluate(route.parsed_command)
    assert decision.level is SecurityLevel.BLOCKED


def test_parser_builds_structured_known_commands_without_shell(tmp_path: Path) -> None:
    parser = TerminalParser()
    assert parser.parse("ejecuta git status", tmp_path).argv == ["git", "status", "--short", "--branch"]
    assert parser.parse("dime mi versión de Python", tmp_path).argv == ["python", "--version"]
    assert parser.parse("crea un entorno virtual", tmp_path).args == ("-m", "venv", ".venv")
    assert parser.parse("instala requirements.txt", tmp_path).risk_level is SecurityLevel.CONFIRMATION
    assert parser.parse("ejecuta npm install", tmp_path).requires_confirmation
    assert parser.parse("ejecuta docker ps", tmp_path).risk_level is SecurityLevel.SAFE
    assert parser.parse("ejecuta docker stop api", tmp_path).risk_level is SecurityLevel.SENSITIVE


def test_package_scripts_and_test_selection(tmp_path: Path) -> None:
    package = tmp_path / "package.json"
    package.write_text('{"scripts": {"test": "vitest", "start:dev": "nest start --watch"}}', encoding="utf-8")
    assert set(package_scripts(tmp_path)) == {"test", "start:dev"}
    parser = TerminalParser()
    assert parser.parse("ejecuta los tests", tmp_path).argv == ["npm", "test"]
    assert parser.parse("inicia mi backend NestJS", tmp_path).argv == ["npm", "run", "start:dev"]


def test_working_directory_and_terminal_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    documents = tmp_path / "Documents"
    documents.mkdir()
    project = documents / "CyberSeg"
    project.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    directories = WorkingDirectoryManager(tmp_path)
    assert directories.change_to("Documentos") == documents.resolve()
    assert directories.set_project("CyberSeg") == project.resolve()
    assert directories.parent() == documents.resolve()
    context = TerminalContextInspector(FakeTerminalProvider(), directories).inspect()
    assert context.current_directory == documents.resolve()
    assert context.active_project == "CyberSeg"


def test_history_sanitizes_values_and_does_not_store_output(tmp_path: Path) -> None:
    path = tmp_path / "history.jsonl"
    history = TerminalHistory(path)
    command = TerminalCommand("npm", ("install", "--token", "token-value"), tmp_path, SecurityLevel.CONFIRMATION)
    history.add(command, terminal_result(stdout="API_KEY=should-not-be-persisted"))
    stored = path.read_text(encoding="utf-8")
    assert "token-value" not in stored
    assert "should-not-be-persisted" not in stored
    assert "[REDACTED]" in stored


def test_manager_executes_valid_safe_command_and_stops_failed_sequence(tmp_path: Path) -> None:
    provider = FakeTerminalProvider([terminal_result(), terminal_result(False, stderr="install failed"), terminal_result()])
    manager = make_manager(tmp_path, provider)
    safe = TerminalParser().parse("ejecuta git status", tmp_path)
    assert manager.execute(safe).success
    install = TerminalParser().parse("ejecuta npm install", tmp_path)
    test = TerminalParser().parse("ejecuta pytest", tmp_path)
    result = manager.execute_sequence((install, test))
    assert not result.success
    assert len(provider.commands) == 2
    assert "No ejecuté los pasos posteriores" in result.message


def test_read_only_mode_refuses_modification_but_allows_status(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    manager.set_mode(TerminalMode.READ_ONLY)
    parser = TerminalParser()
    assert manager.execute(parser.parse("ejecuta git status", tmp_path)).success
    assert not manager.execute(parser.parse("ejecuta npm install", tmp_path)).success


def test_terminal_router_classifier_permissions_and_preview(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    router = CommandRouter(terminal_agent=manager)
    route = router.route("Jarvis ejecuta git status")
    assert route.type is RouteType.TERMINAL_COMMAND
    assert route.parsed_command is not None and route.parsed_command.action == "terminal_execute"
    assert PermissionManager().evaluate(route.parsed_command).level is SecurityLevel.SAFE
    install = router.parse("Jarvis ejecuta npm install")
    assert install is not None and PermissionManager().evaluate(install).level is SecurityLevel.CONFIRMATION
    preview = router.execute(router.parse("Jarvis dime que harias con npm install pero no lo ejecutes"))
    assert preview.success and "No he ejecutado" in preview.message
    sequence = router.route("Jarvis instala las dependencias y ejecuta los tests")
    assert sequence.type is RouteType.TERMINAL_COMMAND
    assert sequence.parsed_command is not None and sequence.parsed_command.action == "terminal_sequence"
    assert router.parse("Jarvis detén el backend").action == "terminal_stop_process"


def test_jarvis_shows_terminal_preview_then_executes_only_after_confirmation(tmp_path: Path) -> None:
    provider = FakeTerminalProvider([terminal_result()])
    manager = make_manager(tmp_path, provider)

    class FakeAI:
        def generate_response(self, history: list[dict[str, str]]) -> str:
            return "respuesta"

    jarvis = Jarvis(FakeAI(), ConversationManager(), CommandRouter(terminal_agent=manager), logging.getLogger("test"))  # type: ignore[arg-type]
    requested = jarvis.process("Jarvis ejecuta npm install")
    assert "JARVIS ejecutará" in requested.response
    assert not provider.commands
    confirmed = jarvis.process("Sí")
    assert confirmed.response.startswith("El comando finalizó")
    assert provider.commands[0][0] == ["npm", "install"]
    blocked = jarvis.process("Jarvis formatea el disco C")
    assert "bloqueada" in blocked.response


def test_git_parser_and_result_analyzer() -> None:
    status = parse_porcelain_status("## develop...origin/develop\n M app.py\n?? new.py\n")
    assert (status.branch, status.modified, status.untracked) == ("develop", 1, 1)
    command = TerminalCommand("pytest", (), Path.cwd(), SecurityLevel.CONFIRMATION)
    result = terminal_result(stdout="48 passed, 2 failed in 3.2s")
    assert "48 correctos y 2 fallidos" in summarize_result(command, result)


def test_subprocess_timeout_output_limit_and_safe_python_integration(tmp_path: Path) -> None:
    provider = SubprocessTerminalProvider(max_output=60)
    version = provider.execute([sys.executable, "--version"], tmp_path, 10)
    assert version.success
    output = provider.execute([sys.executable, "-c", "print('x' * 200)"], tmp_path, 10)
    assert "Salida recortada" in output.stdout
    timed_out = provider.execute([sys.executable, "-c", "import time; time.sleep(1)"], tmp_path, 0.01)
    assert timed_out.timed_out and not timed_out.success


def test_environment_inspector_finds_python() -> None:
    inspector = EnvironmentInspector(SubprocessTerminalProvider())
    assert inspector.is_installed("python")
    status = inspector.status("python")
    assert status.installed and status.version


def test_process_manager_only_stops_jarvis_owned_processes(tmp_path: Path) -> None:
    manager = ProcessManager()
    command = TerminalCommand(sys.executable, ("-c", "import time; print('ready'); time.sleep(3)"), tmp_path)
    process = manager.start_process(command, "backend")
    time.sleep(0.05)
    assert manager.stop_process(process.id) is process
    assert manager.stop_process("not-managed") is None


def test_process_output_command_is_routed_without_executing_shell(tmp_path: Path) -> None:
    router = CommandRouter(terminal_agent=make_manager(tmp_path))
    route = router.route("Jarvis muéstrame la salida del backend")
    assert route.type is RouteType.TERMINAL_COMMAND
    assert route.parsed_command is not None and route.parsed_command.action == "terminal_process_output"
