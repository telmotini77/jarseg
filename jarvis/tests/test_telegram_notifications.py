from __future__ import annotations

import threading

from app.notifications.telegram import TelegramNotifier


def test_telegram_notifier_queues_without_duplicate_alerts() -> None:
    sent: list[tuple[str, str, float]] = []
    delivered = threading.Event()

    def sender(message: str, chat_id: str, timeout: float) -> None:
        sent.append((message, chat_id, timeout))
        delivered.set()

    notifier = TelegramNotifier(
        token="token",
        chat_id="chat",
        enabled=True,
        sender=sender,
        deduplication_seconds=30,
    )
    notifier.start()
    try:
        assert notifier.notify("  Alerta\n  temperatura alta  ") is True
        assert notifier.notify("Alerta temperatura alta") is False
        assert delivered.wait(1)
        assert sent == [("Alerta temperatura alta", "chat", 3.0)]
    finally:
        notifier.stop()


def test_telegram_notifier_retries_in_background() -> None:
    attempts = 0
    delivered = threading.Event()

    def sender(_message: str, _chat_id: str, _timeout: float) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("temporary network failure")
        delivered.set()

    notifier = TelegramNotifier(
        token="token",
        chat_id="chat",
        enabled=True,
        sender=sender,
        retry_attempts=1,
        retry_delay_seconds=0.01,
    )
    notifier.start()
    try:
        assert notifier.notify("Aviso") is True
        assert delivered.wait(1)
        assert attempts == 2
    finally:
        notifier.stop()


def test_disabled_telegram_notifier_does_not_queue_alerts() -> None:
    notifier = TelegramNotifier(token="", chat_id="", enabled=True)
    assert notifier.enabled is False
    assert notifier.notify("Aviso") is False
