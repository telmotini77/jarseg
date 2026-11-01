"""Integration test: set JARVIS_TEST_POSTGRES_URL to an isolated test database."""
from datetime import datetime, timezone
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import pytest


@pytest.fixture
def postgres_url(monkeypatch):
    url = os.environ.get("JARVIS_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("JARVIS_TEST_POSTGRES_URL is not configured")
    import psycopg
    from psycopg import sql

    schema = "test_" + uuid4().hex
    with psycopg.connect(url, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {} ").format(sql.Identifier(schema)))
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append(("options", f"-csearch_path={schema}"))
    monkeypatch.setenv("JARVIS_DATABASE_URL", urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)))
    try:
        yield
    finally:
        with psycopg.connect(url, autocommit=True) as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_all_repositories_persist_and_reload(postgres_url, tmp_path):
    from app.memory.repository import MemoryRepository
    from app.users.repository import UserRepository
    from app.tasks.repository import TaskRepository
    from app.automation.routines.repository import RoutineRepository
    from app.automation_engine.repository import AutomationRepository
    from app.automation_engine.models import Automation, ManualTrigger
    from app.iot.repository import IoTRepository
    from app.iot.models import IoTDevice

    path = tmp_path / "unused.db"
    memory = MemoryRepository(path)
    users = UserRepository(path)
    user = users.create("Alice")
    assert users.get_by_name("alice").id == user.id
    record = memory.create_memory("stored in PostgreSQL", user_id=user.id)
    assert memory.get_memory(record.id).content == "stored in PostgreSQL"
    assert MemoryRepository(path).get_memory(record.id).content == "stored in PostgreSQL"
    assert memory.list_memories(user_id=user.id)[0].id == record.id
    conversation = memory.create_conversation()
    memory.add_message(conversation.id, "user", "hello")
    assert memory.list_messages(conversation.id)[0].content == "hello"
    tasks = TaskRepository(path)
    task = tasks.create("remember", datetime.now(timezone.utc))
    assert TaskRepository(path).list_pending()[0].id == task.id
    routines = RoutineRepository(path)
    routines.save("Morning", [])
    assert RoutineRepository(path).get("morning").name == "Morning"
    automation = Automation("Example", ManualTrigger(), (), ())
    automations = AutomationRepository(path)
    automations.save(automation)
    assert AutomationRepository(path).get("example").id == automation.id
    assert automations.set_enabled("EXAMPLE", False)
    devices = IoTRepository(path)
    devices.upsert_device(IoTDevice("one", "Sensor", "sensor"))
    assert IoTRepository(path).get_device("one").name == "Sensor"
    assert len(devices.list_devices()) == 1
    assert memory.stats()["schema_version"] == 6
    assert not path.exists()


def test_postgres_rolls_back_failed_transactions(postgres_url, tmp_path):
    from app.core.database import connect_database
    with connect_database(tmp_path / "unused.db") as connection:
        connection.execute("CREATE TABLE transaction_test (id INTEGER PRIMARY KEY)")
    with pytest.raises(RuntimeError):
        with connect_database(tmp_path / "unused.db") as connection:
            connection.execute("INSERT INTO transaction_test VALUES (?)", (1,))
            raise RuntimeError("cancel")
    with connect_database(tmp_path / "unused.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM transaction_test").fetchone()[0] == 0
