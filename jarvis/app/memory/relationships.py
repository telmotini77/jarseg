from app.memory.models import MemoryRelationship
from app.memory.repository import MemoryRepository


class MemoryRelationshipService:
    def __init__(self, repository: MemoryRepository) -> None:
        self.repository = repository

    def link(self, first: str, second: str, relation: str, confidence: float = 1.0) -> MemoryRelationship:
        return self.repository.create_relationship(first, second, relation, confidence)

    def related_to(self, memory_id: str) -> list[MemoryRelationship]:
        return self.repository.list_relationships(memory_id)
