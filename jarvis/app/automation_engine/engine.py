from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone

from app.agents.context import AgentContext
from app.agents.registry import AgentRegistry
from app.automation_engine.conditions import conditions_match
from app.automation_engine.cooldown import cooldown_active
from app.automation_engine.executor import AutomationExecutor
from app.automation_engine.models import Automation, AutomationRun, EventTrigger, TimeTrigger
from app.automation_engine.policies import AutomationPolicy
from app.automation_engine.repository import AutomationRepository
from app.automation_engine.triggers import event_matches, time_due
from app.events.bus import EventBus
from app.events.models import JarvisEvent


class AutomationEngine:
    def __init__(self, repository: AutomationRepository, agents: AgentRegistry, events: EventBus, *, max_actions: int = 10, cooldown_seconds: int = 60, notifier=None, logger: logging.Logger | None = None) -> None:
        self.repository, self.agents, self.events = repository, agents, events
        self.policy = AutomationPolicy(max_actions)
        self.cooldown_seconds = cooldown_seconds
        self.executor = AutomationExecutor(agents, events, notifier)
        self.logger = logger or logging.getLogger("jarvis.automation")
        self._running: set[str] = set()
        self._running_lock = threading.Lock()
        events.subscribe_all(self._on_event)

    def create(self, automation: Automation) -> Automation:
        self.policy.validate(automation, self.agents)
        return self.repository.save(automation)

    def list(self) -> list[Automation]:
        return self.repository.list()

    def set_enabled(self, identifier: str, enabled: bool) -> bool:
        return self.repository.set_enabled(identifier, enabled)

    def delete(self, identifier: str) -> bool:
        return self.repository.delete(identifier)

    async def run_manual(self, identifier: str, context: AgentContext | None = None) -> AutomationRun:
        automation = self.repository.get(identifier)
        if automation is None or not automation.enabled:
            return AutomationRun(identifier, False, "No encontré una automatización activa.", error="not_found")
        return await self._run(automation, context or AgentContext(automation.id, automation.name), automatic=False)

    def run_time(self, now: datetime) -> None:
        for automation in self.repository.list(enabled_only=True):
            if isinstance(automation.trigger, TimeTrigger) and time_due(automation.trigger, now, automation.last_run_at):
                self._start_background(automation, {"time": now.isoformat()})

    def _on_event(self, event: JarvisEvent) -> None:
        for automation in self.repository.list(enabled_only=True):
            trigger = automation.trigger
            if isinstance(trigger, EventTrigger) and event_matches(trigger, event) and conditions_match(automation.conditions, event.payload):
                self._start_background(automation, event.payload, event.trace_id)

    def _start_background(self, automation: Automation, payload: dict, trace_id: str | None = None) -> None:
        now = datetime.now(timezone.utc)
        if cooldown_active(automation.last_run_at, self.cooldown_seconds, now):
            return
        with self._running_lock:
            if automation.id in self._running:
                return
            self._running.add(automation.id)

        def run() -> None:
            try:
                asyncio.run(self._run(automation, AgentContext(trace_id or automation.id, automation.name, shared_state={"event": payload}), automatic=True))
            finally:
                with self._running_lock:
                    self._running.discard(automation.id)

        threading.Thread(target=run, daemon=True).start()

    async def _run(self, automation: Automation, context: AgentContext, *, automatic: bool) -> AutomationRun:
        self.policy.validate(automation, self.agents)
        run = await self.executor.execute(automation, context, automatic=automatic)
        self.repository.record_run(run)
        self.events.publish(JarvisEvent("AUTOMATION_COMPLETED" if run.success else "AUTOMATION_FAILED", "automation", {"automation_id": automation.id, "name": automation.name}, context.session_id))
        return run
