"""Adaptadores registrados para los agentes especializados de JARVIS."""

from app.agents.base import Agent, AgentHealth, AgentTask
from app.agents.context import AgentContext
from app.agents.registry import AgentRegistry
from app.agents.result import AgentResult
from app.agents.automation_agent import AutomationAgent
from app.agents.browser_agent import BrowserAgent
from app.agents.code_agent import CodeSpecialistAgent
from app.agents.conversation_agent import ConversationAgent
from app.agents.iot_agent import IoTSpecialistAgent
from app.agents.memory_agent import MemoryAgent
from app.agents.system_agent import SystemAgent
from app.agents.terminal_agent import TerminalAgent
from app.agents.vision_agent import VisionAgent
from app.agents.productivity_agent import ProductivitySpecialistAgent
from app.cyberseg.agent import CyberSegAgent

__all__ = [
    "Agent", "AgentHealth", "AgentTask", "AgentContext", "AgentRegistry", "AgentResult",
    "AutomationAgent", "BrowserAgent", "CodeSpecialistAgent", "ConversationAgent", "IoTSpecialistAgent",
    "MemoryAgent", "SystemAgent", "TerminalAgent", "VisionAgent",
    "ProductivitySpecialistAgent",
    "CyberSegAgent",
]
