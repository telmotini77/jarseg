from __future__ import annotations

import asyncio
import logging

from app.agents.context import AgentContext
from app.agents.registry import AgentRegistry
from app.events.bus import EventBus
from app.events.models import JarvisEvent
from app.memory.manager import MemoryManager
from app.orchestrator.dispatcher import AgentDispatcher
from app.orchestrator.executor import PlanExecutor
from app.orchestrator.locks import ResourceLockManager
from app.orchestrator.models import ExecutionPlan, OrchestrationResult, OrchestratorMode, OrchestratorStatus, UserGoal
from app.orchestrator.planner import TaskPlanner
from app.orchestrator.policies import GlobalSecurityPolicy
from app.orchestrator.recovery import RecoveryManager
from app.orchestrator.state import OrchestratorState


class JarvisOrchestrator:
    def __init__(self, registry: AgentRegistry, events: EventBus, *, memory: MemoryManager | None = None, mode: OrchestratorMode = OrchestratorMode.ASSIST, max_retries: int = 2, max_parallel_tasks: int = 3, max_replans: int = 2, logger: logging.Logger | None = None) -> None:
        self.registry, self.events, self.memory, self.mode = registry, events, memory, mode
        self.max_replans = max_replans
        self.logger = logger or logging.getLogger("jarvis.orchestrator")
        self.state = OrchestratorState()
        self.planner, self.policy = TaskPlanner(), GlobalSecurityPolicy()
        self.executor = PlanExecutor(AgentDispatcher(registry), ResourceLockManager(), RecoveryManager(max_retries), events, max_parallel=max_parallel_tasks)

    def create_plan(self, goal_text: str, *, user_id: str | None = None) -> ExecutionPlan:
        self.state.status = OrchestratorStatus.PLANNING
        goal = UserGoal(goal_text, user_id=user_id or (self.memory.active_user_id if self.memory else None), mode=self.mode.value)
        plan = self.planner.plan(goal)
        self.policy.validate(plan, self.registry, self.mode)
        self.state.plan = plan
        self.state.status = OrchestratorStatus.WAITING_CONFIRMATION if self.policy.requires_confirmation(plan) else OrchestratorStatus.PLANNING
        self.events.publish(JarvisEvent("PLAN_CREATED", "orchestrator", {"plan_id": plan.id, "tasks": len(plan.tasks)}, goal.id))
        return plan

    async def process_goal(self, goal_text: str, *, user_id: str | None = None) -> OrchestrationResult:
        try:
            plan = self.create_plan(goal_text, user_id=user_id)
        except ValueError as error:
            self.state.status = OrchestratorStatus.FAILED
            return OrchestrationResult("", False, str(error), error="plan_invalid")
        self.state.status = OrchestratorStatus.EXECUTING
        context = AgentContext(plan.goal_id, goal_text)
        results = await self.executor.execute(plan, context, self.state)
        if self.state.cancelled:
            self.state.status = OrchestratorStatus.CANCELLED
            return OrchestrationResult(plan.id, False, "La tarea multiagente fue cancelada.", results, "cancelled")
        success = bool(results) and all(result.success for result in results.values()) and len(results) == len(plan.tasks)
        self.state.status = OrchestratorStatus.COMPLETED if success else OrchestratorStatus.FAILED
        summary = self._summary(plan, results, success)
        if self.memory is not None and success:
            self.memory.remember(f"Tarea multiagente completada: {summary[:700]}", "conversation", source="system", importance=0.5)
        self.events.publish(JarvisEvent("PLAN_COMPLETED" if success else "PLAN_FAILED", "orchestrator", {"plan_id": plan.id, "completed": len(results), "total": len(plan.tasks)}, plan.goal_id))
        return OrchestrationResult(plan.id, success, summary, results, None if success else "task_failed")

    def process_goal_sync(self, goal_text: str) -> OrchestrationResult:
        return asyncio.run(self.process_goal(goal_text))

    def preview(self, goal_text: str) -> str:
        plan = self.create_plan(goal_text)
        return self.planner.preview(plan)

    def cancel(self) -> str:
        self.state.cancelled = True
        return "Solicité la cancelación segura del plan actual."

    def status(self) -> str:
        if self.state.plan is None:
            return "No hay una tarea multiagente activa."
        total = len(self.state.plan.tasks)
        completed = len(self.state.completed_tasks)
        return f"Estado: {self.state.status.value}. Paso {completed + 1 if completed < total else total} de {total}."

    def set_mode(self, mode: str) -> str:
        self.mode = OrchestratorMode(mode)
        return f"Modo del orquestador: {self.mode.value}."

    @staticmethod
    def _summary(plan: ExecutionPlan, results, success: bool) -> str:
        header = f"Completé {len(results)} de {len(plan.tasks)} pasos." if success else f"Completé {sum(item.success for item in results.values())} de {len(plan.tasks)} pasos."
        details = [f"- {item.summary}" for item in results.values() if item.summary]
        return header + ("\n" + "\n".join(details[:6]) if details else "")
