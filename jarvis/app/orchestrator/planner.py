from __future__ import annotations

import re

from app.agents.base import AgentTask
from app.orchestrator.models import ExecutionPlan, UserGoal


class TaskPlanner:
    """Planificador determinista. Un LLM puede sugerir, pero no se ejecuta JSON libre."""

    @staticmethod
    def _project(text: str) -> str | None:
        match = re.search(r"\b(?:abre|revisa)\s+(?:mi\s+)?([\w.-]+)", text, re.IGNORECASE)
        if not match:
            return None
        value = match.group(1)
        return None if value.casefold() in {"vs", "visual", "el", "mi"} else value

    @staticmethod
    def _task(agent: str, action: str, objective: str, *, dependencies: tuple[str, ...] = (), risk: str = "safe", resources: tuple[str, ...] = (), **parameters: object) -> AgentTask:
        return AgentTask(agent, action, objective, dict(parameters), dependencies, risk, resources)

    def plan(self, goal: UserGoal) -> ExecutionPlan:
        text = goal.text.casefold()
        project = self._project(goal.text)
        tasks: list[AgentTask] = []
        if "cyberseg" in text:
            status = self._task("cyberseg", "cyberseg.status", "Consultar el estado local de CyberSeg", resources=("cyberseg:local",))
            alerts = self._task("cyberseg", "cyberseg.alerts", "Consultar las alertas recientes de CyberSeg", dependencies=(status.id,), resources=("cyberseg:local",), limit=10)
            tasks.extend([status, alerts, self._task("conversation", "conversation.summarize", "Resumir el estado de CyberSeg", dependencies=(alerts.id,))])
        elif "estado del esp32" in text and "backend" in text:
            tasks.extend([
                self._task("iot", "iot.read", "Consultar el estado del ESP32", resources=("iot:default",)),
                self._task("terminal", "terminal.status", "Consultar el estado del backend", resources=("terminal:project",)),
            ])
        elif ("documentacion oficial" in text or "documentación oficial" in text) and ("codigo" in text or "código" in text or "error" in text):
            code = self._task("code", "code.review", "Revisar la implementación local", resources=("project:current",))
            browser = self._task("browser", "browser.search", "Buscar documentación oficial", resources=("browser:session",), query=goal.text)
            tasks.extend([code, browser, self._task("conversation", "conversation.summarize", "Comparar evidencia local y documentación", dependencies=(code.id, browser.id))])
        elif "corrige" in text or "corregir" in text:
            analyze = self._task("code", "code.diagnostics", "Analizar el primer error conocido", resources=("project:current",), output="")
            plan = self._task("code", "code.plan_change", "Preparar una corrección revisable", dependencies=(analyze.id,), risk="confirmation", resources=("project:current",), objective=goal.text)
            tasks.extend([analyze, plan, self._task("conversation", "conversation.summarize", "Resumir la corrección preparada", dependencies=(plan.id,))])
        elif "abre vs code" in text or "abre visual studio code" in text:
            vscode = self._task("system", "system.open_application", "Abrir VS Code", risk="confirmation", resources=("system:apps",), application="vscode")
            tasks.append(vscode)
            if "backend" in text:
                tasks.append(self._task("terminal", "terminal.start_backend", "Iniciar backend", dependencies=(vscode.id,), risk="confirmation", resources=("terminal:project",)))
            if "navegador" in text or "documentacion" in text or "documentación" in text:
                tasks.append(self._task("browser", "browser.open", "Abrir documentación", risk="confirmation", resources=("browser:session",), target="https://docs.nestjs.com"))
        elif "temperatura" in text and ("avisa" in text or "avisame" in text or "avísame" in text):
            value = re.search(r"(\d+(?:[.,]\d+)?)", text)
            threshold = float(value.group(1).replace(",", ".")) if value else 30.0
            tasks.append(self._task("iot", "iot.create_rule", "Crear alerta de temperatura", risk="confirmation", resources=("iot:default",), sensor="temperature", operator=">", threshold=threshold, action="notify"))
        elif "tests" in text or "pruebas" in text:
            resolve = self._task("memory", "memory.resolve_project", "Localizar el proyecto solicitado", resources=(f"project:{project or 'current'}",), project=project or "")
            open_project = self._task("system", "system.open_project", "Abrir el proyecto", dependencies=(resolve.id,), risk="confirmation", resources=(f"project:{project or 'current'}",))
            tests = self._task("terminal", "terminal.run_tests", "Ejecutar los tests", dependencies=(resolve.id,), risk="confirmation", resources=(f"terminal:{project or 'current'}",))
            review = self._task("code", "code.diagnostics", "Analizar los fallos de tests", dependencies=(tests.id,), resources=(f"project:{project or 'current'}",), output="")
            summary = self._task("conversation", "conversation.summarize", "Resumir el resultado", dependencies=(open_project.id, tests.id, review.id))
            tasks.extend([resolve, open_project, tests, review, summary])
        elif "revisa" in text or "pendiente" in text:
            resolve = self._task("memory", "memory.resolve_project", "Localizar el proyecto", resources=(f"project:{project or 'current'}",), project=project or "")
            review = self._task("code", "code.review", "Revisar el proyecto", dependencies=(resolve.id,), resources=(f"project:{project or 'current'}",))
            tasks.extend([resolve, review, self._task("conversation", "conversation.summarize", "Resumir pendientes", dependencies=(review.id,))])
        else:
            tasks.append(self._task("conversation", "conversation.summarize", "Resumir el objetivo solicitado"))
        return ExecutionPlan(goal.id, tuple(tasks))

    @staticmethod
    def preview(plan: ExecutionPlan) -> str:
        lines = [f"{index}. {task.agent}: {task.objective}" for index, task in enumerate(plan.tasks, 1)]
        return "Plan multiagente:\n" + "\n".join(lines)
