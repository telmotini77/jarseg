from __future__ import annotations

import asyncio
from pathlib import Path

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.code.agent import CodeAgent


class CodeSpecialistAgent(Agent):
    def __init__(self, code: CodeAgent | None) -> None:
        self.code = code

    @property
    def name(self) -> str:
        return "code"

    @property
    def capabilities(self) -> set[str]:
        return {"code.analyze", "code.run_tests", "code.review", "code.plan_change", "code.diagnostics"}

    @property
    def health(self) -> AgentHealth:
        return AgentHealth.HEALTHY if self.code is not None else AgentHealth.UNAVAILABLE

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        if self.code is None:
            return AgentResult(task.id, self.name, False, summary="Code Agent no está disponible.", error="unavailable")
        try:
            path = task.parameters.get("path") or context.shared_state.get("active_project_path")
            if path and (self.code.current_project is None or self.code.current_project.root_path != Path(str(path)).resolve()):
                project = await asyncio.to_thread(self.code.analyze_project, str(path))
                context.shared_state["active_project_path"] = str(project.root_path)
            if task.action == "code.analyze":
                project = self.code.current_project or await asyncio.to_thread(self.code.analyze_project)
                summary = f"Proyecto {project.name}: {', '.join(project.frameworks or project.languages) or 'stack no detectado'}."
                return AgentResult(task.id, self.name, True, {"project": project.name, "files": len(project.files)}, summary)
            if task.action == "code.run_tests":
                output = await asyncio.to_thread(self.code.run_tests)
                success = "fall" not in output.casefold() and "error" not in output.casefold()
                return AgentResult(task.id, self.name, success, {"output": output}, output, None if success else "tests_failed")
            if task.action == "code.review":
                output = await asyncio.to_thread(self.code.review)
                return AgentResult(task.id, self.name, True, {"review": output}, output)
            if task.action == "code.diagnostics":
                output = str(task.parameters.get("output", ""))
                if not output:
                    for previous in reversed(list(context.shared_state.get("task_results", {}).values())):
                        candidate = getattr(previous, "data", {}).get("output")
                        if candidate:
                            output = str(candidate)
                            break
                if not output:
                    return AgentResult(task.id, self.name, True, {"diagnostics": []}, "No hubo errores de tests para analizar.")
                diagnostics = await asyncio.to_thread(self.code.diagnostics, output)
                text = "\n".join(item.message for item in diagnostics[:5]) or "No encontré diagnósticos estructurados."
                return AgentResult(task.id, self.name, True, {"diagnostics": diagnostics}, text)
            if task.action == "code.plan_change":
                plan = await asyncio.to_thread(self.code.plan_change, str(task.parameters.get("objective", task.objective)))
                preview = await asyncio.to_thread(self.code.preview_plan, plan.id)
                return AgentResult(task.id, self.name, True, {"plan_id": plan.id, "risk": plan.risk_level.value}, preview)
        except (OSError, ValueError) as error:
            return AgentResult(task.id, self.name, False, summary=str(error), error="code_failed")
        return AgentResult(task.id, self.name, False, summary="Acción de código no registrada.", error="unsupported_action")
