from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from app.productivity.agenda import daily_agenda
from app.productivity.calendar import CalendarProvider, conflicts
from app.productivity.email import EmailProvider, summarize
from app.productivity.models import CalendarEvent, EmailDraft, EmailMessage, ProductivityContext


class ProductivityAgent:
    def __init__(self, calendar: CalendarProvider | None, email: EmailProvider | None, timezone_name: str = "America/Guayaquil") -> None:
        self.calendar, self.email, self.zone = calendar, email, ZoneInfo(timezone_name)

    def get_daily_agenda(self, when: datetime | None = None) -> str:
        now = (when or datetime.now(self.zone)).astimezone(self.zone); start = now.replace(hour=0, minute=0, second=0, microsecond=0); end = start + timedelta(days=1)
        return daily_agenda(self._events(start, end), start.replace(hour=8), start.replace(hour=20))

    def get_upcoming_events(self, days: int = 7) -> list[CalendarEvent]:
        now = datetime.now(self.zone); return self._events(now, now + timedelta(days=days))

    def create_event(self, event: CalendarEvent) -> CalendarEvent:
        if self.calendar is None: raise ValueError("Calendar Provider no está disponible.")
        existing = self._events(event.start - timedelta(days=1), event.end + timedelta(days=1)); overlap = conflicts(event, existing)
        if overlap: raise ValueError("Hay conflicto con: " + ", ".join(item.title for item in overlap))
        return self.calendar.create_event(event)

    def search_email(self, query: str, limit: int = 10) -> list[EmailMessage]:
        if self.email is None: raise ValueError("Email Provider no está disponible.")
        return self.email.search(query, limit)

    def get_important_emails(self) -> str: return summarize(self.search_email("is:important", 10))
    def summarize_email(self, query: str) -> str: return summarize(self.search_email(query, 20))
    def create_email_draft(self, recipient: str, subject: str, body: str, reply_to: str | None = None) -> EmailDraft:
        if self.email is None: raise ValueError("Email Provider no está disponible.")
        return self.email.create_draft(recipient, subject, body, reply_to)
    def context(self) -> ProductivityContext:
        events = self.get_upcoming_events(1) if self.calendar else []; emails = self.search_email("is:unread", 50) if self.email else []
        return ProductivityContext(events[0] if events else None, sum("IMPORTANT" in item.labels for item in emails), sum(item.unread for item in emails), 0)
    def _events(self, start: datetime, end: datetime) -> list[CalendarEvent]: return self.calendar.list_events(start, end) if self.calendar else []
