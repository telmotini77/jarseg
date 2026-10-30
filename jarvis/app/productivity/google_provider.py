from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.productivity.calendar import CalendarProvider
from app.productivity.email import EmailProvider
from app.productivity.models import CalendarEvent, EmailDraft, EmailMessage, ProviderHealth


_SCOPES = ("https://www.googleapis.com/auth/calendar.events", "https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.compose")


class GoogleWorkspaceProvider(CalendarProvider, EmailProvider):
    """Google Calendar/Gmail con OAuth local; nunca recibe ni guarda contraseñas."""
    name = "google"

    def __init__(self, credentials_file: str, token_file: str) -> None:
        self.credentials_file, self.token_file = Path(credentials_file), Path(token_file)
        self._credentials = None

    def health(self) -> str:
        return ProviderHealth.CONNECTED.value if self._credentials and self._credentials.valid else ProviderHealth.AUTH_REQUIRED.value

    def authorize(self) -> str:
        if not self.credentials_file.is_file(): raise ValueError("No encontré el archivo de credenciales OAuth de Google.")
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        credentials = Credentials.from_authorized_user_file(str(self.token_file), _SCOPES) if self.token_file.is_file() else None
        if credentials and credentials.expired and credentials.refresh_token: credentials.refresh(Request())
        if not credentials or not credentials.valid:
            credentials = InstalledAppFlow.from_client_secrets_file(str(self.credentials_file), _SCOPES).run_local_server(port=0)
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        self.token_file.write_text(credentials.to_json(), encoding="utf-8")
        self._credentials = credentials
        return "Google Calendar y Gmail quedaron autorizados localmente."

    def _calendar(self):
        if self.health() != ProviderHealth.CONNECTED.value: raise ValueError("Google requiere autorización OAuth.")
        from googleapiclient.discovery import build
        return build("calendar", "v3", credentials=self._credentials, cache_discovery=False)

    def list_events(self, start: datetime, end: datetime) -> list[CalendarEvent]:
        rows = self._calendar().events().list(calendarId="primary", timeMin=start.astimezone(timezone.utc).isoformat(), timeMax=end.astimezone(timezone.utc).isoformat(), singleEvents=True, orderBy="startTime").execute().get("items", [])
        return [CalendarEvent(item["id"], item.get("summary", "Sin título"), datetime.fromisoformat(item["start"].get("dateTime", f"{item['start']['date']}T00:00:00+00:00")), datetime.fromisoformat(item["end"].get("dateTime", f"{item['end']['date']}T00:00:00+00:00")), item.get("location"), item.get("description"), tuple(person.get("email", "") for person in item.get("attendees", [])), "primary", self.name) for item in rows]

    def create_event(self, event: CalendarEvent) -> CalendarEvent:
        body = {"summary": event.title, "start": {"dateTime": event.start.isoformat()}, "end": {"dateTime": event.end.isoformat()}, "location": event.location or "", "description": event.description or "", "attendees": [{"email": value} for value in event.attendees]}
        item = self._calendar().events().insert(calendarId=event.calendar_id, body=body, sendUpdates="none").execute()
        return CalendarEvent(item["id"], event.title, event.start, event.end, event.location, event.description, event.attendees, event.calendar_id, self.name)

    def search(self, query: str, limit: int = 10) -> list[EmailMessage]:
        if self.health() != ProviderHealth.CONNECTED.value: raise ValueError("Gmail requiere autorización OAuth.")
        from googleapiclient.discovery import build
        service = build("gmail", "v1", credentials=self._credentials, cache_discovery=False)
        rows = service.users().messages().list(userId="me", q=query, maxResults=min(limit, 25)).execute().get("messages", [])
        result = []
        for row in rows:
            item = service.users().messages().get(userId="me", id=row["id"], format="metadata", metadataHeaders=["From", "To", "Subject", "Date"]).execute(); headers = {x["name"].casefold(): x["value"] for x in item.get("payload", {}).get("headers", [])}
            result.append(EmailMessage(item["id"], item.get("threadId", item["id"]), headers.get("from", "desconocido"), tuple(headers.get("to", "").split(",")) if headers.get("to") else (), headers.get("subject", "Sin asunto"), item.get("snippet", ""), datetime.fromtimestamp(int(item.get("internalDate", "0")) / 1000, timezone.utc), tuple(item.get("labelIds", [])), bool(item.get("payload", {}).get("parts")), "UNREAD" in item.get("labelIds", []), "gmail"))
        return result

    def create_draft(self, recipient: str, subject: str, body: str, reply_to: str | None = None) -> EmailDraft:
        if self.health() != ProviderHealth.CONNECTED.value: raise ValueError("Gmail requiere autorización OAuth.")
        return EmailDraft(str(uuid4()), recipient, subject, body, reply_to)
