from app.events.bus import EventBus
from app.experience.service import ExperienceService
from app.experience.states import JarvisVisualState


def test_experience_publishes_safe_hud_state() -> None:
    events = []
    bus = EventBus(); bus.subscribe_all(events.append)
    experience = ExperienceService(bus)
    experience.set_state(JarvisVisualState.LISTENING, transcript="Jarvis abre YouTube", level=0.6)
    assert experience.public_snapshot()["visual_state"] == "listening"
    assert events[-1].event_type == "JARVIS_STATE"
    assert events[-1].payload["transcript"] == "Jarvis abre YouTube"
