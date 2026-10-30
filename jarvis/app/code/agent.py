from __future__ import annotations

import shutil
from pathlib import Path

from app.code.analyzer import CodeAnalyzer
from app.code.context import CodeContextBuilder
from app.code.diagnostics import parse_diagnostics
from app.code.editor import CodeEditor
from app.code.models import CodeAgentMode, CodeChangePlan, CodeRiskLevel, PatchApplyResult, ProjectContext
from app.code.planner import ChangePlanner
from app.code.project import ProjectInspector
from app.code.project_builder import ProjectBuilder, ProjectBuildPlan
from app.code.search import CodeSearch
from app.code.security import validate_project_path
from app.code.test_runner import CodeTestRunner
from app.code.validator import CodeValidator
from app.code.integrations.vscode import VSCodeIntegration
from app.memory.manager import MemoryManager
from app.terminal.manager import TerminalManager
from app.terminal.models import CommandSource, TerminalCommand
from app.terminal.security import classified
from app.security.permissions import SecurityLevel


class CodeAgent:
    """Fachada del Code Agent: analiza primero y modifica solo con un plan confirmado."""

    def __init__(
        self,
        terminal: TerminalManager,
        memory: MemoryManager | None = None,
        *,
        mode: CodeAgentMode = CodeAgentMode.ASSIST,
        inspector: ProjectInspector | None = None,
        search: CodeSearch | None = None,
        planner: ChangePlanner | None = None,
        editor: CodeEditor | None = None,
        validator: CodeValidator | None = None,
        vscode_enabled: bool = True,
        max_fix_attempts: int = 3,
        max_context_tokens: int = 2_000,
        auto_run_tests: bool = True,
        auto_run_lint: bool = True,
        project_builder: ProjectBuilder | None = None,
    ) -> None:
        self.terminal = terminal
        self.memory = memory
        self.mode = mode
        self.inspector = inspector or ProjectInspector()
        self.search = search or CodeSearch()
        self.analyzer = CodeAnalyzer(self.search.reader)
        self.planner = planner or ChangePlanner()
        self.editor = editor or CodeEditor()
        self.validator = validator or CodeValidator()
        self.tests = CodeTestRunner(terminal, self.validator)
        self.vscode = VSCodeIntegration(terminal, vscode_enabled)
        self.max_fix_attempts = max_fix_attempts
        self.context_builder = CodeContextBuilder(self.search, max_characters=max_context_tokens * 4)
        self.auto_run_tests = auto_run_tests
        self.auto_run_lint = auto_run_lint
        self.project_builder = project_builder
        self.current_project: ProjectContext | None = None
        self.plans: dict[str, CodeChangePlan] = {}
        self.last_plan_id: str | None = None
        self.changed_files: set[Path] = set()
        self.last_diff = ""
        self.project_plans: dict[str, ProjectBuildPlan] = {}
        self.last_project_plan_id: str | None = None

    def analyze_project(self, root: str | Path | None = None) -> ProjectContext:
        directory = self._resolve_project(root)
        context = self.inspector.inspect(directory)
        self.current_project = context
        if self.memory is not None:
            self.memory.index_project(str(context.root_path), context.name)
            self.memory.update_working(active_project=context.name, current_topic=f"Código: {context.name}")
        return context

    def search_code(self, query: str, *, symbols: bool = False):
        context = self._project()
        return self.search.symbols(query, context) if symbols else self.search.text(query, context)

    def explain_code(self, target: str) -> str:
        context = self._project()
        direct = (context.root_path / target).resolve()
        if direct.is_file() and validate_project_path(direct, context.root_path):
            return self.analyzer.explain_file(direct, context)
        files = self.search.files(target, context, limit=2)
        if len(files) == 1:
            return self.analyzer.explain_file(files[0], context)
        symbols = self.search.symbols(target, context, limit=3)
        if symbols:
            return "Encontré: " + "; ".join(f"{item.path.relative_to(context.root_path)}:{item.line} {item.snippet}" for item in symbols)
        return "No encontré un archivo o símbolo único para explicar."

    def plan_change(self, objective: str) -> CodeChangePlan:
        context = self._project()
        plan = self.planner.plan(objective, context)
        self.plans[plan.id] = plan
        self.last_plan_id = plan.id
        return plan

    def preview_plan(self, plan_id: str | None = None) -> str:
        plan = self._plan(plan_id)
        steps = [f"{index}. {step}" for index, step in enumerate(self._plan_steps(plan), 1)]
        diff = self.editor.patcher.preview(plan.patches, self._project().root_path) if plan.patches else "No hay parche automático: requiere revisión de código y una decisión explícita."
        return "Plan:\n" + "\n".join(steps) + f"\nRiesgo: {plan.risk_level.value}.\n\nDiff previsto:\n{diff}"

    def apply_change(self, plan_id: str | None = None) -> PatchApplyResult:
        if self.mode is CodeAgentMode.READ_ONLY:
            raise ValueError("Code Agent está en modo read_only; no puede modificar archivos.")
        plan = self._plan(plan_id)
        if plan.risk_level is CodeRiskLevel.RESTRICTED:
            raise ValueError("El plan afecta archivos protegidos o eliminaciones y fue bloqueado.")
        if not plan.patches:
            raise ValueError("Este plan no tiene un parche determinista para aplicar automáticamente.")
        self._ensure_clean_git()
        if plan.risk_level is CodeRiskLevel.SENSITIVE:
            self._backup_existing(plan)
        result = self.editor.patcher.apply(plan.patches, self._project().root_path)
        self.changed_files.update(result.changed_files)
        self.last_diff = result.diff
        validation_messages: list[str] = []
        if self.auto_run_lint:
            validation_messages.append(self.run_lint())
        if self.auto_run_tests:
            validation_messages.append(self.run_tests())
        if self.memory is not None:
            self.memory.remember(
                f"Cambio de código aplicado en {self._project().name}: {plan.objective}", "conversation",
                source="system", importance=0.65,
            )
        message = result.message + ("\nValidación:\n" + "\n".join(validation_messages) if validation_messages else "")
        return PatchApplyResult(result.changed_files, result.diff, message)

    def run_validation(self) -> str:
        return self.tests.run(self._project(), "all")

    def run_tests(self) -> str:
        return self.tests.run(self._project(), "tests")

    def run_lint(self) -> str:
        return self.tests.run(self._project(), "lint")

    def run_build(self) -> str:
        return self.tests.run(self._project(), "build")

    def diagnostics(self, output: str):
        return parse_diagnostics(output, self._project().root_path)

    def architecture(self) -> str:
        return self.analyzer.architecture(self._project())

    def dependencies(self) -> str:
        return self.analyzer.dependencies(self._project())

    def review(self) -> str:
        findings = self.analyzer.review(self._project())
        if not findings:
            return "No encontré patrones estáticos preocupantes en los archivos revisables."
        return "\n".join(f"- [{item.severity}] {item.path.relative_to(self._project().root_path) if item.path else 'proyecto'}:{item.line or '-'} {item.message}" for item in findings)

    def build_context(self, request: str) -> str:
        memory = self.memory.build_context(request) if self.memory is not None else ""
        return self.context_builder.build(request, self._project(), memory)

    def open_vscode(self, target: str | None = None, line: int | None = None):
        context = self._project()
        if target:
            path = (context.root_path / target).resolve()
            if not path.is_file() or not validate_project_path(path, context.root_path):
                raise ValueError("No encontré un archivo seguro dentro del proyecto activo.")
            return self.vscode.open_file(path, context.root_path, line)
        return self.vscode.open_project(context.root_path)

    def changed_summary(self) -> str:
        context = self._project()
        if not self.changed_files:
            return "No he modificado archivos en esta operación."
        return "Archivos modificados por JARVIS:\n" + "\n".join(f"- {path.relative_to(context.root_path)}" for path in sorted(self.changed_files))

    def show_diff(self) -> str:
        return self.last_diff or "No hay un diff de cambios aplicados por JARVIS en esta operación."

    def create_commit(self, message: str | None = None) -> str:
        context = self._project()
        if not self.changed_files:
            return "No hay archivos modificados por JARVIS para incluir en un commit selectivo."
        relative_files = tuple(str(path.relative_to(context.root_path)) for path in sorted(self.changed_files))
        status = self.terminal.execute(classified(TerminalCommand(
            "git", ("status", "--short", "--branch"), context.root_path, SecurityLevel.SAFE, False, CommandSource.INTERNAL,
        )))
        if not status.success:
            return "No pude comprobar el estado Git antes del commit."
        stage = self.terminal.execute(classified(TerminalCommand(
            "git", ("add", "--", *relative_files), context.root_path, SecurityLevel.CONFIRMATION, True, CommandSource.INTERNAL,
        )))
        if not stage.success:
            return "No pude preparar únicamente los archivos modificados por JARVIS. " + stage.message
        commit_message = message or "feat(code-agent): apply approved changes"
        commit = self.terminal.execute(classified(TerminalCommand(
            "git", ("commit", "-m", commit_message), context.root_path, SecurityLevel.CONFIRMATION, True, CommandSource.INTERNAL,
        )))
        return commit.message

    def plan_project(self, objective: str) -> ProjectBuildPlan:
        if self.project_builder is None:
            raise ValueError("Project Builder no está configurado. Configura un proveedor de IA para crear proyectos por prompt.")
        plan = self.project_builder.plan(objective)
        self.project_plans[plan.id] = plan
        self.last_project_plan_id = plan.id
        return plan

    def preview_project(self, plan_id: str | None = None) -> str:
        if self.project_builder is None:
            raise ValueError("Project Builder no está configurado.")
        return self.project_builder.preview(self._project_plan(plan_id))

    def apply_project(self, plan_id: str | None = None) -> PatchApplyResult:
        if self.mode is CodeAgentMode.READ_ONLY:
            raise ValueError("Code Agent está en modo read_only; no puede crear proyectos.")
        if self.project_builder is None:
            raise ValueError("Project Builder no está configurado.")
        plan = self._project_plan(plan_id)
        result = self.project_builder.apply(plan)
        self.changed_files.update(result.changed_files)
        self.last_diff = result.diff
        self.current_project = self.inspector.inspect(plan.root)
        return result

    def _project(self) -> ProjectContext:
        return self.current_project or self.analyze_project()

    def _resolve_project(self, root: str | Path | None) -> Path:
        if root is None:
            return self.terminal.cwd.resolve()
        candidate = Path(root)
        if candidate.exists():
            return candidate.resolve()
        if self.memory is not None:
            query = str(root).casefold()
            matches = [project for project in self.memory.repository.list_projects() if query in {project.id.casefold(), project.name.casefold()}]
            if len(matches) == 1:
                return Path(matches[0].root_path).resolve()
        raise ValueError("No encontré una ruta segura para ese proyecto. Selecciónalo primero con Terminal Agent o guárdalo en memoria.")

    def _plan(self, plan_id: str | None) -> CodeChangePlan:
        selected = plan_id or self.last_plan_id
        if not selected or selected not in self.plans:
            raise ValueError("No hay un plan de cambio pendiente.")
        return self.plans[selected]

    def _project_plan(self, plan_id: str | None) -> ProjectBuildPlan:
        selected = plan_id or self.last_project_plan_id
        if not selected or selected not in self.project_plans:
            raise ValueError("No hay un proyecto propuesto pendiente.")
        return self.project_plans[selected]

    @staticmethod
    def _plan_steps(plan: CodeChangePlan) -> list[str]:
        steps = [f"Crear {path.name}" for path in plan.files_to_create]
        steps.extend(f"Modificar {path.name}" for path in plan.files_to_modify)
        steps.extend(f"Validar: {step}" for step in plan.validation_steps)
        return steps or ["Analizar los archivos relevantes antes de proponer un parche."]

    def _backup_existing(self, plan: CodeChangePlan) -> None:
        root = self._project().root_path
        destination = root / ".jarvis-code-backups" / plan.id
        for path in plan.files_to_modify:
            if path.is_file() and validate_project_path(path, root):
                relative = path.relative_to(root)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)

    def _ensure_clean_git(self) -> None:
        root = self._project().root_path
        if not (root / ".git").exists():
            return
        status = self.terminal.execute(classified(TerminalCommand(
            "git", ("status", "--short", "--branch"), root, SecurityLevel.SAFE, False, CommandSource.INTERNAL,
        )))
        if not status.success:
            raise ValueError("No pude comprobar Git antes de editar; no aplicaré el parche.")
        if "Tienes 0 archivos" not in status.message:
            raise ValueError("El repositorio ya contiene cambios sin confirmar. No sobrescribiré cambios del usuario.")
