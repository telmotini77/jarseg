from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import os
from typing import Any

import psutil

from app.api.dependencies import DashboardContext
from app.api.websocket import public_data


def _item(value: Any) -> Any:
    return public_data(asdict(value) if is_dataclass(value) else value)


class DashboardState:
    def __init__(self, context: DashboardContext, gateway) -> None:
        self.context, self.gateway = context, gateway

    def metrics(self) -> dict[str, Any]:
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("C:\\" if os.name == "nt" else "/")
        battery = psutil.sensors_battery()
        counters = psutil.net_io_counters()
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory": {"used": memory.used, "total": memory.total, "percent": memory.percent},
            "disk": {"free": disk.free, "total": disk.total, "percent": disk.percent},
            "battery_percent": battery.percent if battery else None,
            "network": {"sent": counters.bytes_sent, "received": counters.bytes_recv},
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def agents(self) -> list[dict[str, Any]]:
        busy_agent = None
        orchestrator = self.context.orchestrator
        if orchestrator and orchestrator.state.plan and orchestrator.state.current_task_id:
            for task in orchestrator.state.plan.tasks:
                if task.id == orchestrator.state.current_task_id:
                    busy_agent = task.agent
                    break
        return [
            {
                "id": name, "name": f"{name.title()} Agent", "health": agent.health.value,
                "status": "busy" if name == busy_agent else ("offline" if agent.health.value == "unavailable" else "idle"),
                "capabilities": sorted(agent.capabilities), "current_task": orchestrator.state.current_task_id if name == busy_agent and orchestrator else None,
            }
            for name, agent in ((name, self.context.agents.get(name)) for name in self.context.agents.names())
        ]

    def tasks(self) -> list[dict[str, Any]]:
        orchestrator = self.context.orchestrator
        if not orchestrator or not orchestrator.state.plan:
            return []
        plan = orchestrator.state.plan
        results = orchestrator.state.completed_tasks
        task_rows = []
        for index, task in enumerate(plan.tasks, 1):
            status = "completed" if task.id in results else "running" if task.id == orchestrator.state.current_task_id else "queued"
            task_rows.append({"id": task.id, "index": index, "agent": task.agent, "action": task.action, "objective": task.objective, "status": status, "risk": task.risk_level})
        return [{
            "id": plan.id, "goal_id": plan.goal_id, "status": orchestrator.state.status.value,
            "progress": {"completed": len(results), "total": len(plan.tasks)}, "current_task_id": orchestrator.state.current_task_id,
            "tasks": task_rows, "created_at": plan.created_at.isoformat(),
        }]

    def automations(self) -> list[dict[str, Any]]:
        engine = self.context.automations
        if engine is None:
            return []
        return [_item(item) for item in engine.list()]

    def iot_devices(self) -> list[dict[str, Any]]:
        iot = self.context.iot
        if iot is None:
            return []
        rows: list[dict[str, Any]] = []
        for device in iot.devices.list():
            state = iot.states.get(device.id)
            rows.append({
                "id": device.id, "name": device.name, "status": device.status, "trusted": device.trusted,
                "capabilities": list(device.capabilities), "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                "state": _item(state) if state else None,
            })
        return rows

    def processes(self) -> list[dict[str, Any]]:
        terminal = self.context.terminal
        return [_item(item) for item in terminal.process_manager.list_managed_processes()] if terminal else []

    def code(self) -> dict[str, Any]:
        code = self.context.code
        if code is None:
            return {"available": False}
        project = code.current_project
        return {"available": True, "project": _item(project) if project else None, "changed_files": [str(path) for path in sorted(code.changed_files)], "last_diff": code.last_diff}

    def browser(self) -> dict[str, Any]:
        browser = self.context.browser
        if browser is None:
            return {"available": False}
        tabs = browser.list_tabs()
        current = browser.current_page()
        return {
            "available": True,
            "navigator": browser.navigator_status(),
            "tabs": tabs.message if tabs.success else "",
            "current_page": current.message if current.success else "",
        }

    def memory(self) -> dict[str, Any]:
        memory = self.context.memory
        if memory is None:
            return {"available": False}
        return {"available": True, "stats": public_data(memory.stats()), "projects": [_item(item) for item in memory.repository.list_projects()]}

    def cyberseg(self) -> dict[str, Any]:
        client = self.context.cyberseg
        if client is None:
            return {"available": False, "status": "disabled"}
        try:
            return {"available": True, "status": client.status(), "alerts": client.recent_alerts()}
        except Exception:
            return {"available": True, "status": "unavailable", "alerts": ""}

    def status(self) -> dict[str, Any]:
        agents = self.agents()
        return {
            "version": "v1.4" if self.context.users else "v1.1", "online": True, "active_user": _item(self.context.users.active_user()) if self.context.users and self.context.users.active_user() else None, "agents": {"healthy": sum(item["health"] != "unavailable" for item in agents), "total": len(agents)},
            "experience": self.context.experience.public_snapshot() if self.context.experience else {"visual_state": "idle", "interface_mode": "dashboard", "level": 0.0},
            "orchestrator_mode": self.context.orchestrator.mode.value if self.context.orchestrator else "disabled",
            "orchestrator_status": self.context.orchestrator.state.status.value if self.context.orchestrator else "disabled",
            "terminal_mode": self.context.terminal.mode.value if self.context.terminal else "disabled",
            "wake_word": "listening" if self.context.wake_word else "disabled",
            "microphone": "ready" if self.context.microphone else "unavailable",
            "tasks": self.tasks(), "automations_active": sum(item["enabled"] for item in self.automations()),
            "iot_online": sum(item["status"] == "online" for item in self.iot_devices()), "metrics": self.metrics(),
            "cyberseg": self.cyberseg(),
        }
