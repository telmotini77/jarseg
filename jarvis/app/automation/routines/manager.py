from __future__ import annotations

import logging

from app.automation.action import Action
from app.automation.registry import is_registered_action
from app.automation.routines.models import Routine, RoutineDraft
from app.automation.routines.repository import RoutineRepository
from app.commands.apps import APP_ALIASES
from app.commands.files import FOLDER_ALIASES
from app.security.permissions import SecurityLevel


_ROUTINE_ALLOWED_ACTIONS = frozenset({"open_application", "open_folder", "open_url", "system_info"})


class RoutineManager:
    def __init__(self, repository: RoutineRepository, logger: logging.Logger | None = None) -> None:
        self.repository = repository
        self._draft: RoutineDraft | None = None
        self._logger = logger or logging.getLogger("jarvis.routines")

    def begin(self, name: str) -> RoutineDraft:
        self._draft = RoutineDraft(name.strip())
        return self._draft

    def add_action_from_text(self, instruction: str) -> Action | None:
        if self._draft is None:
            return None
        normalized = instruction.casefold().strip()
        if normalized.startswith("abre "):
            target = normalized.removeprefix("abre ").strip()
            if target in APP_ALIASES:
                action = Action("open_application", APP_ALIASES[target], security_level=SecurityLevel.SAFE)
            elif target in FOLDER_ALIASES:
                action = Action("open_folder", target, security_level=SecurityLevel.SAFE)
            else:
                return None
            self._draft.actions.append(action)
            return action
        return None

    def save_draft(self) -> Routine | None:
        if self._draft is None or not self._draft.actions:
            return None
        routine = self._save(self._draft.name, self._draft.actions)
        self._draft = None
        return routine

    def create(self, name: str, actions: list[Action]) -> Routine:
        return self._save(name, actions)

    def get(self, name: str) -> Routine | None:
        return self.repository.get(name)

    def _save(self, name: str, actions: list[Action]) -> Routine:
        for action in actions:
            if not is_registered_action(action.action_type) or action.action_type not in _ROUTINE_ALLOWED_ACTIONS:
                raise ValueError("Las rutinas solo pueden guardar acciones seguras registradas.")
        routine = self.repository.save(name, actions)
        self._logger.info("ROUTINE action=create name=%s action_count=%s", routine.name, len(routine.actions))
        return routine
