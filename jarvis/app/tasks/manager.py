from __future__ import annotations

import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from app.tasks.models import Reminder, TaskStatus
from app.tasks.parser import parse_schedule, split_reminder_request
from app.tasks.repository import TaskRepository


class ReminderManager:
    def __init__(self, repository: TaskRepository, timezone_name: str, logger: logging.Logger | None = None) -> None:
        self.repository = repository
        self.timezone_name = timezone_name
        self._logger = logger or logging.getLogger("jarvis.tasks")

    def create_from_text(self, text: str, now: datetime) -> Reminder:
        title, schedule_text = split_reminder_request(text)
        schedule = parse_schedule(schedule_text, now, self.timezone_name)
        reminder = self.repository.create(title, schedule.trigger_at, schedule.recurrence)
        self._logger.info("REMINDER action=create trigger=%s", reminder.trigger_at.isoformat())
        return reminder

    def list_pending(self) -> list[Reminder]:
        return self.repository.list_pending()

    def list_today(self, now: datetime) -> list[Reminder]:
        zone = ZoneInfo(self.timezone_name)
        today = now.astimezone(zone).date()
        return [item for item in self.list_pending() if item.trigger_at.astimezone(zone).date() == today]

    def cancel(self, query: str) -> tuple[Reminder | None, list[Reminder]]:
        matches = self.repository.find_pending(query)
        if len(matches) != 1:
            return None, matches
        self.repository.update_status(matches[0].id, TaskStatus.CANCELLED)
        self._logger.info("REMINDER action=cancel")
        return matches[0], matches

    def complete(self, query: str) -> tuple[Reminder | None, list[Reminder]]:
        matches = self.repository.find_pending(query)
        if len(matches) != 1:
            return None, matches
        self.repository.update_status(matches[0].id, TaskStatus.COMPLETED)
        return matches[0], matches

    def due(self, now: datetime) -> list[Reminder]:
        return self.repository.list_due(now)

    def mark_triggered(self, reminder: Reminder) -> None:
        if reminder.recurrence == "daily":
            self.repository.reschedule(reminder.id, reminder.trigger_at + timedelta(days=1))
        elif reminder.recurrence and reminder.recurrence.startswith("weekly:"):
            self.repository.reschedule(reminder.id, reminder.trigger_at + timedelta(days=7))
        else:
            self.repository.update_status(reminder.id, TaskStatus.COMPLETED)
