from app.ai.prompts import SYSTEM_PROMPT


def test_system_prompt_requests_brief_voice_friendly_responses() -> None:
    assert "una a tres frases breves" in SYSTEM_PROMPT
    assert "No uses Markdown" in SYSTEM_PROMPT
