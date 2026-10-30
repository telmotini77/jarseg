from __future__ import annotations

from app.agents.registry import AgentRegistry
from app.automation_engine.actions import AUTOMATION_ACTIONS, action_key
from app.automation_engine.models import Automation, EventTrigger, TimeTrigger
from app.automation_engine.conditions import OPERATORS


class AutomationPolicy:
    def __init__(self, max_actions: int = 10) -> None:
        self.max_actions = max_actions

    def validate(self, automation: Automation, registry: AgentRegistry) -> None:
        if not automation.name.strip() or not automation.actions or len(automation.actions) > self.max_actions:
            raise ValueError("La automatización debe tener entre 1 y el máximo de acciones permitido.")
        if isinstance(automation.trigger, TimeTrigger) and automation.trigger.frequency != "daily":
            raise ValueError("Por ahora solo se admiten horarios diarios seguros.")
        if isinstance(automation.trigger, EventTrigger) and not automation.trigger.event_type:
            raise ValueError("El evento de automatización es obligatorio.")
        for condition in automation.conditions:
            if condition.operator not in OPERATORS:
                raise ValueError("La automatización contiene un operador no permitido.")
        for action in automation.actions:
            if action_key(action) not in AUTOMATION_ACTIONS:
                raise ValueError("La automatización contiene una acción no registrada.")
            if action.action != "notify" and not registry.is_registered_action(action.agent, action.action):
                raise ValueError("La automatización intenta usar un agente o acción no registrada.")
            if action.risk_level in {"restricted", "blocked"}:
                raise ValueError("Las automatizaciones no permiten acciones restringidas o bloqueadas.")

    @staticmethod
    def automatic_allowed(automation: Automation) -> bool:
        return all(action.risk_level == "safe" for action in automation.actions)
