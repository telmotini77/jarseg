from __future__ import annotations

from app.agents.registry import AgentRegistry
from app.orchestrator.models import ExecutionPlan, OrchestratorMode


_RISK_ORDER = {"safe": 1, "confirmation": 2, "sensitive": 3, "restricted": 4, "blocked": 5}
_READ_ONLY = {"memory.resolve_project", "memory.recall", "conversation.summarize", "code.analyze", "code.review", "code.diagnostics", "browser.search", "browser.read", "iot.read", "iot.list_devices", "cyberseg.status", "cyberseg.alerts", "terminal.status"}


class GlobalSecurityPolicy:
    def validate(self, plan: ExecutionPlan, registry: AgentRegistry, mode: OrchestratorMode) -> None:
        task_ids = {task.id for task in plan.tasks}
        if len(task_ids) != len(plan.tasks):
            raise ValueError("El plan contiene IDs de tarea duplicados.")
        for task in plan.tasks:
            if not registry.is_registered_action(task.agent, task.action):
                raise ValueError(f"La tarea usa una acción no registrada: {task.agent}.{task.action}.")
            if task.risk_level not in _RISK_ORDER or _RISK_ORDER[task.risk_level] >= _RISK_ORDER["restricted"]:
                raise ValueError("El plan contiene una acción restringida o bloqueada.")
            if mode is OrchestratorMode.READ_ONLY and task.action not in _READ_ONLY:
                raise ValueError("El modo read_only no permite esa tarea del plan.")
            if mode is OrchestratorMode.AUTONOMOUS_SAFE and task.risk_level != "safe":
                raise ValueError("El modo autonomous_safe solo permite tareas seguras.")
            if any(dependency not in task_ids for dependency in task.dependencies):
                raise ValueError("El plan contiene una dependencia inexistente.")
        self._validate_acyclic(plan)

    @staticmethod
    def _validate_acyclic(plan: ExecutionPlan) -> None:
        graph = {task.id: set(task.dependencies) for task in plan.tasks}
        resolved: set[str] = set()
        while graph:
            ready = {identifier for identifier, dependencies in graph.items() if dependencies <= resolved}
            if not ready:
                raise ValueError("El plan contiene dependencias circulares.")
            resolved.update(ready)
            for identifier in ready:
                del graph[identifier]

    @staticmethod
    def requires_confirmation(plan: ExecutionPlan) -> bool:
        return any(task.risk_level in {"confirmation", "sensitive"} for task in plan.tasks)
