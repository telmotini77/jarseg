from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, Request, status


class LocalDashboardSecurity:
    """Token efímero para escrituras; el servidor solo se liga a loopback."""

    def __init__(self, host: str) -> None:
        if host not in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}:
            raise ValueError("El dashboard v1.1 solo puede exponerse en loopback o 0.0.0.0.")
        self.token = secrets.token_urlsafe(32)

    def session(self) -> dict[str, str]:
        return {"token": self.token}

    def require_write(self, request: Request, x_jarvis_dashboard_token: str | None = Header(default=None)) -> None:
        origin = request.headers.get("origin", "")
        if origin and not origin.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Origen no permitido.")
        if not x_jarvis_dashboard_token or not secrets.compare_digest(x_jarvis_dashboard_token, self.token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Sesión local no válida.")


class MobileApiSecurity:
    """Token guard for the deliberately small mobile read-only API."""

    def __init__(self, *, enabled: bool, token: str) -> None:
        self._enabled = enabled
        self._token = token

    def require_read(self, x_jarvis_mobile_token: str | None) -> None:
        if not self._enabled:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Acceso móvil no activado.")
        if not self._token or not x_jarvis_mobile_token or not secrets.compare_digest(x_jarvis_mobile_token, self._token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Credencial móvil no válida.")
