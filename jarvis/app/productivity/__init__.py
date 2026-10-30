"""Productivity Agent v1.2: agenda local, correo seguro y proveedores OAuth."""

from app.productivity.agent import ProductivityAgent
from app.productivity.models import CalendarEvent, EmailDraft, EmailMessage, PriorityItem, ProductivityContext

__all__ = ["ProductivityAgent", "CalendarEvent", "EmailDraft", "EmailMessage", "PriorityItem", "ProductivityContext"]
