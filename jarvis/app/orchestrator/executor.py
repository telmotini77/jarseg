from __future__ import annotations

import asyncio
from collections.abc import Callable

from app.agents.context import AgentContext
from app.agents.result import AgentResult
from app.events.bus import EventBus
from app.events.models import JarvisEvent
from app.orchestrator.dispatcher import AgentDispatcher
from app.orchestrator.locks import ResourceLockManager
from app.orchestrator.models import ExecutionPlan
from app.orchestrator.recovery import RecoveryManager
from app.orchestrator.state import OrchestratorState
from app.orchestrator.verifier import Verifier


class PlanExecutor:
    def __init__(self, dispatcher: AgentDispatcher, locks: ResourceLockManager, recovery: RecoveryManager, events: EventBus, *, max_parallel: int = 3, task_timeout: float = 90.0) -> None:
        self.dispatcher, self.locks, self.recovery, self.events = dispatcher, locks, recovery, events
        self.max_parallel, self.task_timeout = max_parallel, task_timeout

    async def execute(self, plan: ExecutionPlan, context: AgentContext, state: OrchestratorState) -> dict[str, AgentResult]:
        pending = {task.id: task for task in plan.tasks}
        results: dict[str, AgentResult] = {}
        context.shared_state["task_results"] = results
        while pending:
            if state.cancelled:
                break
            ready = [task for task in pending.values() if all(dep in results and results[dep].success for dep in task.dependencies)]
            if not ready:
                break
            batch = ready[:self.max_parallel]
            values = await asyncio.gather(*(self._run(task, context, state) for task in batch))
            for task, result in zip(batch, values):
                results[task.id] = result
                pending.pop(task.id, None)
                state.completed_tasks.add(task.id)
                self.events.publish(JarvisEvent("AGENT_COMPLETED" if result.success else "AGENT_FAILED", task.agent, {"task_id": task.id, "action": task.action, "success": result.success}, context.session_id))
                if not result.success:
                    for dependent_id, dependent in tuple(pending.items()):
                        if task.id in dependent.dependencies:
                            pending.pop(dependent_id)
        return results

    async def _run(self, task, context: AgentContext, state: OrchestratorState) -> AgentResult:
        state.current_task_id = task.id
        self.events.publish(JarvisEvent("AGENT_STARTED", task.agent, {"task_id": task.id, "action": task.action}, context.session_id))
        attempt = 0
        while True:
            try:
                async with self.locks.acquire(task.resources):
                    result = await asyncio.wait_for(self.dispatcher.resolve(task.agent).execute(task, context), timeout=self.task_timeout)
                if Verifier.verify(result) or not self.recovery.may_retry(task, attempt):
                    return result
            except asyncio.TimeoutError:
                result = AgentResult(task.id, task.agent, False, summary="El agente excedió el tiempo permitido.", error="timeout")
                if not self.recovery.may_retry(task, attempt):
                    return result
            except Exception as error:
                result = AgentResult(task.id, task.agent, False, summary=f"Falló el agente {task.agent}: {error}", error="agent_exception")
                if not self.recovery.may_retry(task, attempt):
                    return result
            attempt += 1
