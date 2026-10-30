from __future__ import annotations

import base64
import hashlib
import hmac
import os


class PasswordHasher:
    """Password verifier; bcrypt is used when installed, with secure scrypt fallback."""

    def hash(self, secret: str) -> str:
        if not secret:
            raise ValueError("La contraseña no puede estar vacía.")
        try:
            import bcrypt
            return "bcrypt$" + bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()
        except ImportError:
            salt = os.urandom(16)
            derived = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1)
            return "scrypt$" + base64.b64encode(salt + derived).decode()

    def verify(self, secret: str, stored: str | None) -> bool:
        if not stored:
            return False
        if stored.startswith("bcrypt$"):
            try:
                import bcrypt
                return bcrypt.checkpw(secret.encode(), stored.removeprefix("bcrypt$").encode())
            except ImportError:
                return False
        if stored.startswith("scrypt$"):
            raw = base64.b64decode(stored.removeprefix("scrypt$"))
            return hmac.compare_digest(raw[16:], hashlib.scrypt(secret.encode(), salt=raw[:16], n=2**14, r=8, p=1))
        return False
