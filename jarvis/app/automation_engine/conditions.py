from __future__ import annotations

from app.automation_engine.models import Condition


OPERATORS = {
    "==": lambda left, right: left == right,
    "!=": lambda left, right: left != right,
    ">": lambda left, right: left > right,
    "<": lambda left, right: left < right,
    ">=": lambda left, right: left >= right,
    "<=": lambda left, right: left <= right,
    "contains": lambda left, right: right in left,
}


def conditions_match(conditions: tuple[Condition, ...], payload: dict) -> bool:
    for condition in conditions:
        if condition.operator not in OPERATORS or condition.field not in payload:
            return False
        try:
            if not OPERATORS[condition.operator](payload[condition.field], condition.value):
                return False
        except (TypeError, ValueError):
            return False
    return True
