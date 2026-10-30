from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class CommandRequest(BaseModel):
    text: str = Field(min_length=1, max_length=1_000)


class AutomationActionInput(BaseModel):
    agent: Literal["system", "terminal", "iot", "automation"]
    action: Literal["system.open_application", "system.open_project", "terminal.run_tests", "iot.read", "iot.create_rule", "notify"]
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: Literal["safe", "confirmation"] = "safe"


class AutomationCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    trigger_type: Literal["manual", "time", "event"]
    time: str | None = None
    event_type: str | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    actions: list[AutomationActionInput] = Field(min_length=1, max_length=20)

    @field_validator("time")
    @classmethod
    def validate_time(cls, value: str | None) -> str | None:
        if value is not None and (len(value) != 5 or value[2] != ":" or not value.replace(":", "").isdigit()):
            raise ValueError("La hora debe usar formato HH:MM.")
        return value


class AutomationUpdateRequest(BaseModel):
    enabled: bool


class UserCreateRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    role: Literal["owner", "standard", "guest"] = "standard"
    language: str = Field(default="es", min_length=2, max_length=16)
    timezone: str = Field(default="America/Guayaquil", max_length=64)
    password: str | None = Field(default=None, min_length=4, max_length=256)


class UserUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=80)
    language: str | None = Field(default=None, min_length=2, max_length=16)
    timezone: str | None = Field(default=None, max_length=64)
    response_style: str | None = Field(default=None, max_length=32)
    preferred_voice: str | None = Field(default=None, max_length=128)


class SessionLoginRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)
    password: str | None = Field(default=None, max_length=256)


class PreferenceUpdateRequest(BaseModel):
    values: dict[str, str] = Field(default_factory=dict, max_length=30)
