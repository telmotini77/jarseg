from pathlib import Path

from app.memory.manager import MemoryManager
from app.memory.repository import MemoryRepository
from app.users.manager import UserManager
from app.users.models import UserRole


def _services(path: Path):
    memory = MemoryManager(MemoryRepository(path))
    return memory, UserManager(path, memory, auth_enabled=False)


def test_private_memory_is_invisible_after_user_switch(tmp_path: Path) -> None:
    memory, users = _services(tmp_path / "jarvis.db")
    users.repository.create("Alice")
    users.repository.create("Bob")
    users.switch("Alice")
    memory.remember("CyberSeg uses PostgreSQL")
    users.switch("Bob")
    assert memory.recall("CyberSeg PostgreSQL") == []
    users.switch("Alice")
    assert [item.content for item in memory.recall("CyberSeg PostgreSQL")] == ["CyberSeg uses PostgreSQL"]


def test_switch_clears_working_memory_and_profile_defaults(tmp_path: Path) -> None:
    memory, users = _services(tmp_path / "jarvis.db")
    users.repository.create("Alice")
    users.repository.create("Bob")
    users.switch("Alice")
    memory.update_working(last_command="private command")
    users.set_preference("default_project", "alpha")
    users.switch("Bob")
    assert memory.working.get().last_command is None
    assert users.context().default_project is None


def test_guest_permissions_do_not_allow_modifying_agents(tmp_path: Path) -> None:
    _, users = _services(tmp_path / "jarvis.db")
    users.repository.create("Guest", role=UserRole.GUEST)
    users.switch("Guest")
    assert not users.allows("terminal", modifying=True)
    assert not users.allows("code", modifying=True)
    assert users.allows("iot", modifying=False)
