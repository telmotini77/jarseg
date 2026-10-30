from __future__ import annotations

from app.automation_engine.models import AutomationAction


AUTOMATION_ACTIONS = frozenset({"notify", "system.open_application", "system.open_project", "terminal.run_tests", "iot.read", "iot.create_rule"})


def action_key(action: AutomationAction) -> str:
    if action.action == "notify":
        return "notify"
    return action.action if "." in action.action else f"{action.agent}.{action.action}"
