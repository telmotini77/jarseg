from app.users.models import VoiceProfile

class SpeakerIdentificationProvider:
    """Extension point only; v1.4 never performs biometric recognition automatically."""
    def identify_speaker(self, audio: bytes) -> str | None:
        return None
