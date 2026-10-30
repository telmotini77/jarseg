from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.dependencies import DashboardContext
from app.api.schemas import AutomationCreateRequest, AutomationUpdateRequest, CommandRequest, PreferenceUpdateRequest, SessionLoginRequest, UserCreateRequest, UserUpdateRequest
from app.users.models import UserRole
from app.api.security import LocalDashboardSecurity, MobileApiSecurity
from app.api.state import DashboardState
from app.api.websocket import WebSocketGateway, public_data
from app.automation_engine.models import Automation, AutomationAction, EventTrigger, ManualTrigger, TimeTrigger


class ActionResponse(BaseModel):
    response: str
    should_exit: bool = False


class DashboardStaticFiles(StaticFiles):
    """Entrega index.html para rutas de React sin interceptar /api ni /ws."""

    async def get_response(self, path: str, scope: dict[str, Any]):
        try:
            response = await super().get_response(path, scope)
            return await super().get_response("index.html", scope) if response.status_code == 404 else response
        except StarletteHTTPException as error:
            if error.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


def _automation_from_request(request: AutomationCreateRequest) -> Automation:
    if request.trigger_type == "time":
        if request.time is None:
            raise ValueError("Indica la hora de la automatización.")
        trigger = TimeTrigger(request.time)
    elif request.trigger_type == "event":
        if request.event_type is None:
            raise ValueError("Indica el tipo de evento.")
        trigger = EventTrigger(request.event_type, request.filters)
    else:
        trigger = ManualTrigger()
    actions = tuple(AutomationAction(item.agent, item.action, item.parameters, item.risk_level) for item in request.actions)
    return Automation(request.name, trigger, (), actions)


def create_app(context: DashboardContext, *, host: str = "127.0.0.1", static_dir: Path | None = None) -> FastAPI:
    security = LocalDashboardSecurity(host)
    mobile_security = MobileApiSecurity(
        enabled=bool(getattr(context.settings, "mobile_api_enabled", False)),
        token=str(getattr(context.settings, "mobile_api_token", "")),
    )
    gateway = WebSocketGateway()
    state = DashboardState(context, gateway)
    context.events.subscribe_all(gateway.publish)
    app = FastAPI(title="JARVIS v1.4 API", docs_url=None, redoc_url=None)
    app.state.dashboard_security = security
    app.state.mobile_security = mobile_security
    app.state.gateway = gateway
    app.state.context = context
    port = getattr(context.settings, "dashboard_port", 8765)
    allowed_origins = [f"http://{host}", f"http://{host}:5173"]
    if host == "0.0.0.0":
        allowed_origins.extend([
            "http://127.0.0.1",
            f"http://127.0.0.1:{port}",
            "http://localhost",
            f"http://localhost:{port}",
            "http://[::1]",
            f"http://[::1]:{port}",
        ])
    app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=False, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-Jarvis-Dashboard-Token"])

    def write_access(request: Request, x_jarvis_dashboard_token: Annotated[str | None, Header()] = None) -> None:
        security.require_write(request, x_jarvis_dashboard_token)

    @app.get("/api/session")
    def session() -> dict[str, str]:
        return security.session()

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        return state.status()

    @app.get("/api/experience")
    def experience() -> dict[str, Any]:
        if context.experience is None:
            return {"visual_state": "idle", "interface_mode": "dashboard", "level": 0.0}
        return context.experience.public_snapshot()

    def users_or_503():
        if context.users is None: raise HTTPException(503, "Perfiles de usuario no disponibles.")
        return context.users

    @app.get("/api/users")
    def users_list() -> list[dict[str, Any]]:
        manager = users_or_503()
        return [public_data(user) for user in manager.repository.list()]

    @app.post("/api/users")
    def users_create(payload: UserCreateRequest, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        manager = users_or_503()
        active = manager.active_user()
        if active is None or active.role is not UserRole.OWNER: raise HTTPException(403, "Solo el Owner puede crear perfiles.")
        try:
            hashed = manager.hasher.hash(payload.password) if payload.password else None
            user = manager.repository.create(payload.display_name, role=UserRole(payload.role), language=payload.language, timezone=payload.timezone, password_hash=hashed)
        except ValueError as error: raise HTTPException(400, str(error)) from error
        return public_data(user)

    @app.get("/api/users/me")
    def users_me() -> dict[str, Any]:
        manager = users_or_503(); user = manager.active_user()
        if user is None: raise HTTPException(423, "Sesión bloqueada.")
        return public_data(user)

    @app.patch("/api/users/me")
    def users_me_update(payload: UserUpdateRequest, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        manager = users_or_503(); user = manager.active_user()
        if user is None: raise HTTPException(423, "Sesión bloqueada.")
        return public_data(manager.repository.update(user.id, **payload.model_dump(exclude_none=True)))

    @app.get("/api/users/me/preferences")
    def user_preferences() -> dict[str, str]:
        manager = users_or_503(); user = manager.active_user()
        if user is None: raise HTTPException(423, "Sesión bloqueada.")
        return manager.repository.preferences(user.id)

    @app.patch("/api/users/me/preferences")
    def user_preferences_update(payload: PreferenceUpdateRequest, request: Request, _: None = Depends(write_access)) -> dict[str, str]:
        manager = users_or_503()
        for key, value in payload.values.items(): manager.set_preference(key, value)
        user = manager.active_user()
        return manager.repository.preferences(user.id) if user else {}

    @app.post("/api/session/login")
    def session_login(payload: SessionLoginRequest, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        try: return public_data(users_or_503().switch(payload.display_name, payload.password))
        except PermissionError as error: raise HTTPException(401, str(error)) from error
        except ValueError as error: raise HTTPException(404, str(error)) from error

    @app.post("/api/session/logout")
    def session_logout(request: Request, _: None = Depends(write_access)) -> dict[str, bool]:
        users_or_503().sessions.end_session(); return {"logged_out": True}

    @app.post("/api/session/lock")
    def session_lock(request: Request, _: None = Depends(write_access)) -> dict[str, bool]:
        users_or_503().lock(); return {"locked": True}

    @app.post("/api/session/switch")
    def session_switch(payload: SessionLoginRequest, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        return session_login(payload, request)

    @app.patch("/api/users/{user_id}")
    def user_update(user_id: str, payload: UserUpdateRequest, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        manager=users_or_503(); active=manager.active_user()
        if active is None or active.role is not UserRole.OWNER: raise HTTPException(403, "Solo el Owner puede modificar perfiles.")
        user=manager.repository.update(user_id, **payload.model_dump(exclude_none=True))
        if user is None: raise HTTPException(404, "Perfil no encontrado.")
        return public_data(user)

    @app.post("/api/users/{user_id}/disable")
    def user_disable(user_id: str, request: Request, _: None = Depends(write_access)) -> dict[str, bool]:
        manager=users_or_503(); active=manager.active_user()
        if active is None or active.role is not UserRole.OWNER: raise HTTPException(403, "Solo el Owner puede deshabilitar perfiles.")
        if active.id == user_id: raise HTTPException(400, "No puedes deshabilitar el perfil activo.")
        if not manager.repository.disable(user_id): raise HTTPException(404, "Perfil no encontrado.")
        return {"disabled": True}

    @app.get("/api/agents")
    def agents() -> list[dict[str, Any]]:
        return state.agents()

    @app.get("/api/agents/{agent_id}")
    def agent(agent_id: str) -> dict[str, Any]:
        for item in state.agents():
            if item["id"] == agent_id:
                return item
        raise HTTPException(404, "Agente no encontrado.")

    @app.get("/api/tasks")
    def tasks() -> list[dict[str, Any]]:
        return state.tasks()

    @app.get("/api/tasks/{task_id}")
    def task(task_id: str) -> dict[str, Any]:
        for item in state.tasks():
            if item["id"] == task_id:
                return item
        raise HTTPException(404, "Tarea no encontrada.")

    @app.post("/api/tasks/{task_id}/cancel")
    def cancel_task(task_id: str, request: Request, _: None = Depends(write_access)) -> dict[str, str]:
        orchestrator = context.orchestrator
        if orchestrator is None or not orchestrator.state.plan or orchestrator.state.plan.id != task_id:
            raise HTTPException(404, "No hay una tarea activa con ese ID.")
        return {"message": orchestrator.cancel()}

    @app.get("/api/automations")
    def automations() -> list[dict[str, Any]]:
        return state.automations()

    @app.post("/api/automations")
    def create_automation(payload: AutomationCreateRequest, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        if context.automations is None:
            raise HTTPException(503, "Automation Engine no disponible.")
        try:
            saved = context.automations.create(_automation_from_request(payload))
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        return public_data(saved)

    @app.patch("/api/automations/{automation_id}")
    def update_automation(automation_id: str, payload: AutomationUpdateRequest, request: Request, _: None = Depends(write_access)) -> dict[str, bool]:
        if context.automations is None or not context.automations.set_enabled(automation_id, payload.enabled):
            raise HTTPException(404, "Automatización no encontrada.")
        return {"enabled": payload.enabled}

    @app.delete("/api/automations/{automation_id}")
    def delete_automation(automation_id: str, request: Request, _: None = Depends(write_access)) -> dict[str, bool]:
        if context.automations is None or not context.automations.delete(automation_id):
            raise HTTPException(404, "Automatización no encontrada.")
        return {"deleted": True}

    @app.post("/api/automations/{automation_id}/run")
    async def run_automation(automation_id: str, request: Request, _: None = Depends(write_access)) -> dict[str, Any]:
        if context.automations is None:
            raise HTTPException(503, "Automation Engine no disponible.")
        result = await context.automations.run_manual(automation_id)
        return public_data(result)

    @app.get("/api/system/metrics")
    def metrics() -> dict[str, Any]:
        return state.metrics()

    @app.get("/api/iot/devices")
    def iot_devices() -> list[dict[str, Any]]:
        return state.iot_devices()

    @app.get("/api/iot/devices/{device_id}")
    def iot_device(device_id: str) -> dict[str, Any]:
        for item in state.iot_devices():
            if item["id"] == device_id:
                return item
        raise HTTPException(404, "Dispositivo no encontrado.")

    @app.get("/api/iot/devices/{device_id}/telemetry")
    def telemetry(device_id: str, sensor: str | None = None, limit: int = 60) -> list[dict[str, Any]]:
        if context.iot is None:
            raise HTTPException(503, "IoT Agent no disponible.")
        return [public_data(item) for item in context.iot.telemetry.latest(device_id, sensor, max(1, min(limit, 300)))]

    @app.get("/api/processes")
    def processes() -> list[dict[str, Any]]:
        return state.processes()

    @app.get("/api/code")
    def code() -> dict[str, Any]:
        return state.code()

    @app.get("/api/browser")
    def browser() -> dict[str, Any]:
        return state.browser()

    @app.get("/api/memory")
    def memory() -> dict[str, Any]:
        return state.memory()

    @app.get("/api/cyberseg")
    def cyberseg() -> dict[str, Any]:
        return state.cyberseg()

    @app.get("/api/mobile/status")
    def mobile_status(x_jarvis_mobile_token: Annotated[str | None, Header()] = None) -> dict[str, Any]:
        """Minimal, credential-protected payload for the Android companion."""
        mobile_security.require_read(x_jarvis_mobile_token)
        snapshot = state.status()
        return {
            "online": snapshot["online"],
            "agents": snapshot["agents"],
            "cyberseg": snapshot["cyberseg"],
        }

    @app.get("/api/memory/search")
    def memory_search(query: str, limit: int = 10) -> list[dict[str, Any]]:
        if context.memory is None:
            raise HTTPException(503, "Memory Engine no disponible.")
        return [public_data(item) for item in context.memory.recall(query, limit=max(1, min(limit, 25)))]

    @app.get("/api/productivity/status")
    def productivity_status() -> dict[str, Any]:
        provider = context.productivity.calendar if context.productivity else None
        return {"available": context.productivity is not None, "calendar": provider.health() if provider else "disabled", "email": context.productivity.email.health() if context.productivity and context.productivity.email else "disabled"}

    @app.get("/api/calendar/today")
    def calendar_today() -> dict[str, Any]:
        if context.productivity is None: raise HTTPException(503, "Productivity Agent no disponible.")
        return {"agenda": context.productivity.get_daily_agenda(), "events": public_data(context.productivity.get_upcoming_events(1))}

    @app.get("/api/mail/important")
    def mail_important() -> dict[str, str]:
        if context.productivity is None: raise HTTPException(503, "Productivity Agent no disponible.")
        return {"summary": context.productivity.get_important_emails()}

    @app.post("/api/integrations/google/connect")
    def connect_google(request: Request, _: None = Depends(write_access)) -> dict[str, str]:
        provider = context.productivity.calendar if context.productivity else None
        if provider is None or not hasattr(provider, "authorize"): raise HTTPException(503, "Google Integration no disponible.")
        try: return {"message": provider.authorize()}
        except ValueError as error: raise HTTPException(400, str(error)) from error

    @app.get("/api/history")
    @app.get("/api/logs")
    @app.get("/api/notifications")
    def history(limit: int = 100) -> list[dict[str, Any]]:
        return gateway.history[-max(1, min(limit, 250)):]

    @app.get("/api/settings/public")
    def public_settings() -> dict[str, Any]:
        return {
            "theme": "dark", "dashboard_host": host, "dashboard_port": getattr(context.settings, "dashboard_port", 8765),
            "metrics_interval": getattr(context.settings, "dashboard_system_metrics_interval", 2),
            "telemetry_interval": getattr(context.settings, "dashboard_telemetry_interval", 2),
            "wake_word": getattr(context.settings, "wake_word", "jarvis"),
        }

    @app.post("/api/commands", response_model=ActionResponse)
    async def dashboard_command(payload: CommandRequest, request: Request, _: None = Depends(write_access)) -> ActionResponse:
        result = await asyncio.to_thread(context.jarvis.process, payload.text)
        return ActionResponse(response=result.response, should_exit=result.should_exit)

    @app.post("/api/confirmations/{decision}", response_model=ActionResponse)
    async def confirmation(decision: str, request: Request, _: None = Depends(write_access)) -> ActionResponse:
        if decision not in {"approve", "reject"}:
            raise HTTPException(404, "Decisión no registrada.")
        result = await asyncio.to_thread(context.jarvis.process, "sí" if decision == "approve" else "no")
        return ActionResponse(response=result.response, should_exit=result.should_exit)

    @app.websocket("/ws")
    async def websocket(websocket: WebSocket) -> None:
        origin = websocket.headers.get("origin", "")
        if origin and not origin.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
            await websocket.close(code=1008)
            return
        await gateway.serve(websocket)

    if static_dir and (static_dir / "index.html").is_file():
        app.mount("/", DashboardStaticFiles(directory=static_dir, html=True), name="dashboard")
    return app


class DashboardServer:
    def __init__(self, context: DashboardContext, host: str, port: int, static_dir: Path, logger: logging.Logger | None = None) -> None:
        self.context, self.host, self.port, self.static_dir = context, host, port, static_dir
        self.logger = logger or logging.getLogger("jarvis.dashboard")
        self._server: Any | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        import uvicorn

        config = uvicorn.Config(create_app(self.context, host=self.host, static_dir=self.static_dir), host=self.host, port=self.port, log_level="warning", access_log=False)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, name="jarvis-dashboard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None
