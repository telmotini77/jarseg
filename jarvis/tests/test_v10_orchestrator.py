from __future__ import annotations

import asyncio

from app.agents.base import Agent, AgentTask
from app.agents.context import AgentContext
from app.agents.registry import AgentRegistry
from app.agents.result import AgentResult
from app.automation_engine.engine import AutomationEngine
from app.automation_engine.models import Automation, AutomationAction, ManualTrigger
from app.automation_engine.repository import AutomationRepository
from app.commands.router import CommandRouter
from app.events.bus import EventBus
from app.orchestrator.models import OrchestratorMode
from app.orchestrator.orchestrator import JarvisOrchestrator


class FakeAgent(Agent):
    def __init__(self, name: str, capabilities: set[str]) -> None:
        self._name, self._capabilities = name, capabilities
        self.calls: list[AgentTask] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def capabilities(self) -> set[str]:
        return self._capabilities

    async def execute(self, task: AgentTask, context: AgentContext) -> AgentResult:
        self.calls.append(task)
        return AgentResult(task.id, self.name, True, {"action": task.action}, f"{self.name} completó {task.action}.")


def test_orchestrator_executes_registered_safe_plan() -> None:
    registry = AgentRegistry()
    registry.register(FakeAgent("conversation", {"conversation.summarize"}))
    orchestrator = JarvisOrchestrator(registry, EventBus(), mode=OrchestratorMode.ASSIST)

    result = asyncio.run(orchestrator.process_goal("resume este objetivo"))

    assert result.success
    assert "Completé 1 de 1 pasos" in result.summary


def test_orchestrator_rejects_missing_agent() -> None:
    orchestrator = JarvisOrchestrator(AgentRegistry(), EventBus())

    result = asyncio.run(orchestrator.process_goal("revisa CyberSeg y dime qué quedó pendiente"))

    assert not result.success
    assert result.error == "plan_invalid"


def test_automation_manual_run_is_persisted_and_uses_registered_action(tmp_path) -> None:
    registry = AgentRegistry()
    system = FakeAgent("system", {"system.open_application"})
    registry.register(system)
    engine = AutomationEngine(AutomationRepository(tmp_path / "jarvis.db"), registry, EventBus())
    automation = engine.create(Automation(
        "abrir editor", ManualTrigger(), (),
        (AutomationAction("system", "system.open_application", {"application": "vscode"}),),
    ))

    result = asyncio.run(engine.run_manual(automation.name, AgentContext("test", "prueba")))

    assert result.success
    assert len(system.calls) == 1
    assert engine.list()[0].last_run_at is not None


def test_v10_voice_phrases_route_to_orchestrator() -> None:
    router = CommandRouter(orchestrator=object(), agent_registry=object(), automation_engine=object())

    assert router.parse("Jarvis dime qué agentes tienes disponibles").action == "orchestrator_agents"
    assert router.parse("Jarvis activa modo solo lectura").target == "read_only"
    assert router.parse("Jarvis revisa CyberSeg y dime qué quedó pendiente").action == "orchestrator_goal"
    assert router.parse("Jarvis crea modo programación").action == "automation_create_engine"
