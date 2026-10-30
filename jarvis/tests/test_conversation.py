from app.core.conversation import ConversationManager


def test_conversation_keeps_only_configured_turns() -> None:
    history = ConversationManager(max_turns=1)
    history.add_user_message("primera")
    history.add_assistant_message("respuesta")
    history.add_user_message("segunda")

    assert history.messages() == [
        {"role": "assistant", "content": "respuesta"},
        {"role": "user", "content": "segunda"},
    ]


def test_conversation_ignores_blank_messages() -> None:
    history = ConversationManager()
    history.add_user_message("  ")
    assert history.messages() == []
