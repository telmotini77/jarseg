from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi.testclient import TestClient

from app.agents.base import Agent, AgentTask
from app.agents.registry import AgentRegistry
from app.agents.result import AgentResult
from app.api.dependencies import DashboardContext
from app.api.server import create_app
from app.automation_engine.engine import AutomationEngine
from app.automation_engine.repository import AutomationRepository
from app.events.bus import EventBus
from app.events.models import JarvisEvent


@dataclass
class FakeResult:
    response: str
    should_exit: bool = False


class FakeJarvis:
    def process(self, text: str) -> FakeResult:
        return FakeResult(f"Procesado de forma segura: {text}")


class FakeSettings:
    dashboard_port = 8765
    dashboard_system_metrics_interval = 2
    dashboard_telemetry_interval = 2
    wake_word = "jarvis"


class FakeAgent(Agent):
    @property
    def name(self) -> str:
        return "system"

    @property
    def capabilities(self) -> set[str]:
        return {"system.open_application"}

    async def execute(self, task: AgentTask, context) -> AgentResult:
        return AgentResult(task.id, self.name, True, summary="ok")


def client_for(tmp_path, static_dir: Path | None = None) -> TestClient:
    events = EventBus()
    agents = AgentRegistry()
    agents.register(FakeAgent())
    automations = AutomationEngine(AutomationRepository(tmp_path / "jarvis.db"), agents, events)
    context = DashboardContext(
        jarvis=FakeJarvis(), events=events, agents=agents, orchestrator=None, automations=automations,
        terminal=None, code=None, browser=None, iot=None, memory=None, microphone=None, wake_word=None, productivity=None,
        settings=FakeSettings(),
    )
    return TestClient(create_app(context, static_dir=static_dir))


def test_dashboard_status_is_public_and_never_returns_secrets(tmp_path) -> None:
    client = client_for(tmp_path)

    response = client.get("/api/status")

    assert response.status_code == 200
    assert response.json()["version"] == "v1.1"
    assert "token" not in response.text.casefold()


def test_dashboard_writes_require_ephemeral_session_token(tmp_path) -> None:
    client = client_for(tmp_path)
    payload = {"name": "Aviso", "trigger_type": "manual", "actions": [{"agent": "automation", "action": "notify", "parameters": {"message": "hola"}}]}

    assert client.post("/api/automations", json=payload).status_code == 403
    token = client.get("/api/session").json()["token"]
    response = client.post("/api/automations", json=payload, headers={"X-Jarvis-Dashboard-Token": token})

    assert response.status_code == 200
    assert response.json()["name"] == "Aviso"


def test_dashboard_rejects_unregistered_automation_action_at_schema_boundary(tmp_path) -> None:
    client = client_for(tmp_path)
    token = client.get("/api/session").json()["token"]
    payload = {"name": "No", "trigger_type": "manual", "actions": [{"agent": "system", "action": "format_disk"}]}

    response = client.post("/api/automations", json=payload, headers={"X-Jarvis-Dashboard-Token": token})

    assert response.status_code == 422


def test_dashboard_websocket_receives_event_bus_updates(tmp_path) -> None:
    client = client_for(tmp_path)
    with client.websocket_connect("/ws") as socket:
        assert socket.receive_json()["type"] == "connected"
        client.app.state.context.events.publish(JarvisEvent("TELEMETRY_RECEIVED", "iot", {"temperature": 25.3}))
        update = socket.receive_json()
        assert update["type"] == "telemetry.received"
        assert update["data"]["temperature"] == 25.3


def test_production_dashboard_serves_react_routes(tmp_path) -> None:
    static_dir = Path(__file__).parents[1] / "dashboard" / "dist"
    client = client_for(tmp_path, static_dir)

    response = client.get("/agents")

    assert response.status_code == 200
    assert 'id="root"' in response.text
