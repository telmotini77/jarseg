from __future__ import annotations

import shutil
import logging
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from app.code.agent import CodeAgent
from app.code.dependencies import has_dependency
from app.code.diagnostics import parse_diagnostics
from app.code.language_detector import detect_language
from app.code.models import CodeAgentMode, FilePatch, PatchChange
from app.code.patcher import PatchEngine, content_hash
from app.code.project import ProjectInspector
from app.code.reader import CodeReader
from app.code.scanner import ProjectScanner, ScanLimits
from app.code.search import CodeSearch
from app.code.security import validate_project_path
from app.code.integrations.vscode import VSCodeIntegration
from app.commands.base import CommandResult
from app.commands.router import CommandRouter
from app.core.conversation import ConversationManager
from app.core.jarvis import Jarvis


FIXTURES = Path(__file__).with_name("fixtures") / "projects"


@dataclass
class FakeTerminal:
    cwd: Path
    commands: list[object] = field(default_factory=list)

    def execute(self, command: object) -> CommandResult:
        self.commands.append(command)
        return CommandResult(True, "comando ejecutado por Terminal Agent")

    def last_output(self) -> CommandResult:
        return CommandResult(False, "No hay salida de terminal reciente.")


def copy_project(tmp_path: Path, name: str) -> Path:
    destination = tmp_path / name
    shutil.copytree(FIXTURES / name, destination)
    return destination


def test_detects_project_context_languages_frameworks_and_dependencies() -> None:
    context = ProjectInspector().inspect(FIXTURES / "nestjs-example")
    assert "TypeScript" in context.languages
    assert {"NestJS", "Prisma"}.issubset(context.frameworks)
    assert "npm" in context.package_managers and context.has_tests is False
    assert has_dependency(context.root_path, "@nestjs/core")
    python = ProjectInspector().inspect(FIXTURES / "python-example")
    assert "FastAPI" in python.frameworks and python.has_tests
    assert detect_language(Path("component.tsx")) == "TypeScript"


def test_scanner_excludes_gitignore_protected_and_large_files() -> None:
    scanner = ProjectScanner(ScanLimits(max_files=30, max_file_size=1_000, max_total_bytes=8_000, respect_gitignore=True))
    files = scanner.scan(FIXTURES / "nestjs-example")
    names = {item.path.name for item in files}
    assert "ignored.ts" not in names and ".env" not in names and "auth.service.ts" in names


def test_search_symbols_reader_and_context_are_limited_and_safe() -> None:
    context = ProjectInspector().inspect(FIXTURES / "nestjs-example")
    search = CodeSearch()
    symbols = search.symbols("AuthService", context)
    assert symbols and symbols[0].symbol and symbols[0].symbol.kind == "class"
    references = search.references("login", context)
    assert any("login" in item.snippet for item in references)
    with pytest.raises(ValueError):
        CodeReader().read(context.root_path / ".env", context.root_path)


def test_patch_engine_previews_applies_hash_lock_and_sandboxes(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    file = root / "hello.py"
    file.write_text("def hello():\n    return 'old'\n", encoding="utf-8")
    before = file.read_text(encoding="utf-8")
    patch = FilePatch(file, content_hash(before), (PatchChange(2, 2, "    return 'new'\n"),))
    engine = PatchEngine()
    assert "-    return 'old'" in engine.preview((patch,), root)
    result = engine.apply((patch,), root)
    assert "new" in file.read_text(encoding="utf-8") and result.changed_files == (file,)
    with pytest.raises(ValueError):
        engine.apply((patch,), root)
    escaped = FilePatch(root.parent / "outside.py", None, (PatchChange(1, 0, "x = 1\n"),), create=True)
    with pytest.raises(ValueError):
        engine.apply((escaped,), root)
    assert not validate_project_path(root.parent / "outside.py", root)


def test_code_agent_plans_then_applies_only_after_explicit_apply(tmp_path: Path) -> None:
    root = copy_project(tmp_path, "nestjs-example")
    terminal = FakeTerminal(root)
    agent = CodeAgent(terminal)  # type: ignore[arg-type]
    agent.analyze_project(root)
    plan = agent.plan_change("Crea un servicio users")
    preview = agent.preview_plan(plan.id)
    assert "users.service.ts" in preview and not (root / "src" / "users" / "users.service.ts").exists()
    result = agent.apply_change(plan.id)
    assert result.changed_files and (root / "src" / "users" / "users.service.ts").is_file()
    assert "users.service.ts" in agent.changed_summary()
    assert "+export class UsersService" in agent.show_diff()


def test_read_only_mode_and_test_runner_delegate_to_terminal(tmp_path: Path) -> None:
    root = copy_project(tmp_path, "python-example")
    terminal = FakeTerminal(root)
    agent = CodeAgent(terminal, mode=CodeAgentMode.READ_ONLY)  # type: ignore[arg-type]
    agent.analyze_project(root)
    plan = agent.plan_change("Crea un test nuevo")
    with pytest.raises(ValueError):
        agent.apply_change(plan.id)
    writable = CodeAgent(terminal)  # type: ignore[arg-type]
    writable.analyze_project(root)
    assert "Terminal Agent" in writable.run_tests() and terminal.commands


def test_diagnostics_and_vscode_integration_use_safe_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = copy_project(tmp_path, "nestjs-example")
    diagnostics = parse_diagnostics("src/auth/auth.service.ts(7,3): error TS2322: Type mismatch", root)
    assert diagnostics and diagnostics[0].line == 7
    terminal = FakeTerminal(root)
    integration = VSCodeIntegration(terminal)  # type: ignore[arg-type]
    monkeypatch.setattr("app.code.integrations.vscode.which", lambda _name: "C:/Code/code.cmd")
    assert integration.open_file(root / "src" / "auth" / "auth.service.ts", root, 7).success
    assert terminal.commands


class FakeAI:
    def generate_response(self, messages: list[dict[str, str]]) -> str:
        del messages
        return "respuesta"


class DirtyTerminal(FakeTerminal):
    def execute(self, command: object) -> CommandResult:
        self.commands.append(command)
        return CommandResult(True, "Estás en la rama actual. Tienes 2 archivos con cambios o sin seguimiento.")


def test_code_voice_intents_plan_then_confirm_apply(tmp_path: Path) -> None:
    root = copy_project(tmp_path, "nestjs-example")
    agent = CodeAgent(FakeTerminal(root))  # type: ignore[arg-type]
    router = CommandRouter(code_agent=agent)
    assert router.route("Jarvis analiza este proyecto").parsed_command.action == "code_scan_project"
    assert router.route("Jarvis busca AuthService").parsed_command.action == "code_search"
    assert router.route("Jarvis dime qué stack usa").parsed_command.action == "code_architecture"
    assert router.route("Jarvis muéstrame el diff").parsed_command.action == "code_diff"
    assert router.route("Jarvis ejecuta el build").parsed_command.action == "code_run_build"
    assert router.route("Jarvis crea un proyecto para inventario local").parsed_command.action == "code_project_plan"
    jarvis = Jarvis(FakeAI(), ConversationManager(), router, logging.getLogger("v8"))  # type: ignore[arg-type]
    plan = jarvis.process("Jarvis crea un servicio users")
    assert "Plan:" in plan.response and not (root / "src" / "users" / "users.service.ts").exists()
    confirmation = jarvis.process("Jarvis aplica el plan")
    assert "Confirmas" in confirmation.response
    applied = jarvis.process("sí")
    assert "Apliqué cambios" in applied.response and (root / "src" / "users" / "users.service.ts").is_file()


def test_dirty_git_project_is_preserved_before_applying_patch(tmp_path: Path) -> None:
    root = copy_project(tmp_path, "nestjs-example")
    (root / ".git").mkdir()
    agent = CodeAgent(DirtyTerminal(root))  # type: ignore[arg-type]
    agent.analyze_project(root)
    plan = agent.plan_change("Crea un servicio users")
    with pytest.raises(ValueError, match="cambios sin confirmar"):
        agent.apply_change(plan.id)
