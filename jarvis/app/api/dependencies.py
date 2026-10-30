from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.agents.registry import AgentRegistry
from app.automation_engine.engine import AutomationEngine
from app.browser.browser_manager import BrowserManager
from app.code.agent import CodeAgent
from app.core.jarvis import Jarvis
from app.events.bus import EventBus
from app.iot.agent import IoTAgent
from app.memory.manager import MemoryManager
from app.orchestrator.orchestrator import JarvisOrchestrator
from app.terminal.manager import TerminalManager
from app.voice.microphone import Microphone
from app.wakeword.detector import WakeWordDetector
from app.productivity.agent import ProductivityAgent
from app.users.manager import UserManager
from app.cyberseg.client import CyberSegClient


@dataclass(slots=True)
class DashboardContext:
    jarvis: Jarvis
    events: EventBus
    agents: AgentRegistry
    orchestrator: JarvisOrchestrator | None
    automations: AutomationEngine | None
    terminal: TerminalManager | None
    code: CodeAgent | None
    browser: BrowserManager | None
    iot: IoTAgent | None
    memory: MemoryManager | None
    microphone: Microphone | None
    wake_word: WakeWordDetector | None
    productivity: ProductivityAgent | None
    settings: Any
    users: UserManager | None = None
    experience: Any | None = None
    cyberseg: CyberSegClient | None = None
