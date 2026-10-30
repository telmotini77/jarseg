from enum import Enum


class JarvisVisualState(str, Enum):
    IDLE = "idle"
    LISTENING = "listening"
    PROCESSING = "processing"
    SPEAKING = "speaking"
    EXECUTING = "executing"
    ALERT = "alert"
    ERROR = "error"


class InterfaceMode(str, Enum):
    DASHBOARD = "dashboard"
    HUD = "hud"
    OVERLAY = "overlay"
    MINIMAL = "minimal"
