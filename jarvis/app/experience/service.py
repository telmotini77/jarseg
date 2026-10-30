from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.events.models import JarvisEvent
from app.experience.states import InterfaceMode, JarvisVisualState


@dataclass(slots=True)
class ExperienceSnapshot:
    visual_state: JarvisVisualState = JarvisVisualState.IDLE
    interface_mode: InterfaceMode = InterfaceMode.HUD
    agent: str | None = None
    action: str | None = None
    transcript: str | None = None
    response: str | None = None
    level: float = 0.0
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ExperienceService:
    """Single, safe source of HUD state; events expose summaries only."""

    def __init__(self, events, *, enabled: bool = True, mode: str = "hud") -> None:
        self.events, self.enabled = events, enabled
        self.snapshot = ExperienceSnapshot(interface_mode=InterfaceMode(mode))

    def set_state(self, state: JarvisVisualState, *, agent: str | None = None, action: str | None = None, transcript: str | None = None, response: str | None = None, level: float | None = None) -> None:
        self.snapshot.visual_state = state
        self.snapshot.agent = agent if agent is not None else self.snapshot.agent
        self.snapshot.action = action if action is not None else self.snapshot.action
        self.snapshot.transcript = transcript if transcript is not None else self.snapshot.transcript
        self.snapshot.response = response if response is not None else self.snapshot.response
        self.snapshot.level = max(0.0, min(1.0, level)) if level is not None else (0.12 if state is JarvisVisualState.IDLE else 0.52)
        self.snapshot.updated_at = datetime.now(timezone.utc)
        self.events.publish(JarvisEvent("JARVIS_STATE", "experience", self.public_snapshot()))

    def set_voice_level(self, level: float) -> None:
        self.snapshot.level = max(0.0, min(1.0, level))
        self.events.publish(JarvisEvent("VOICE_LEVEL", "voice", {"level": self.snapshot.level}))

    def public_snapshot(self) -> dict[str, str | float | None]:
        return {
            "visual_state": self.snapshot.visual_state.value, "interface_mode": self.snapshot.interface_mode.value,
            "agent": self.snapshot.agent, "action": self.snapshot.action, "transcript": self.snapshot.transcript,
            "response": self.snapshot.response, "level": self.snapshot.level, "updated_at": self.snapshot.updated_at.isoformat(),
        }
