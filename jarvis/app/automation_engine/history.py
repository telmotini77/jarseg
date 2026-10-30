from __future__ import annotations

from app.automation_engine.models import AutomationRun


def history_summary(run: AutomationRun) -> str:
    return run.summary if run.success else f"Falló: {run.summary}"
