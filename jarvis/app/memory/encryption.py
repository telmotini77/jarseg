"""Cifrado opcional de aplicación; requiere una clave aportada por el usuario."""

from __future__ import annotations


class MemoryCipher:
    def __init__(self, enabled: bool = False, key: str | None = None) -> None:
        self.enabled = enabled
        self._fernet = None
        if enabled:
            if not key:
                raise ValueError("MEMORY_ENCRYPTION_KEY es necesaria cuando el cifrado está activo")
            try:
                from cryptography.fernet import Fernet
            except ImportError as error:
                raise RuntimeError("Instala cryptography para activar el cifrado de memoria") from error
            self._fernet = Fernet(key.encode("utf-8"))

    def encrypt(self, content: str) -> str:
        return "enc:" + self._fernet.encrypt(content.encode("utf-8")).decode("utf-8") if self._fernet else content

    def decrypt(self, content: str) -> str:
        if not self._fernet or not content.startswith("enc:"):
            return content
        return self._fernet.decrypt(content.removeprefix("enc:").encode("utf-8")).decode("utf-8")
