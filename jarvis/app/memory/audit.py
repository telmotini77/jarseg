from app.memory.models import MemoryAuditEntry
from app.memory.repository import MemoryRepository


class MemoryAuditService:
    def __init__(self, repository: MemoryRepository) -> None:
        self.repository = repository

    def record(self, action: str, memory_id: str | None = None, **details: object) -> MemoryAuditEntry:
        return self.repository.log_audit(action, memory_id=memory_id, details=details)

    def history(self, memory_id: str | None = None) -> list[MemoryAuditEntry]:
        return self.repository.list_audit(memory_id)
