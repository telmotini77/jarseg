from __future__ import annotations

from dataclasses import dataclass, field

from app.orchestrator.models import ExecutionPlan, OrchestratorStatus


@dataclass(slots=True)
class OrchestratorState:
    status: OrchestratorStatus = OrchestratorStatus.IDLE
    plan: ExecutionPlan | None = None
    current_task_id: str | None = None
    cancelled: bool = False
    paused: bool = False
    completed_tasks: set[str] = field(default_factory=set)

    def reset(self) -> None:
        self.status = OrchestratorStatus.IDLE
        self.plan = None
        self.current_task_id = None
        self.cancelled = False
        self.paused = False
        self.completed_tasks.clear()
