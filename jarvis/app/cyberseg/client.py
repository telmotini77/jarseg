from __future__ import annotations

import json
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


class CyberSegClientError(RuntimeError):
    """Raised when the local CyberSeg service cannot be contacted safely."""


@dataclass(frozen=True, slots=True)
class CyberSegClient:
    api_url: str
    token: str
    timeout_seconds: int = 3
    retry_attempts: int = 2
    retry_backoff_seconds: float = 0.35

    def __post_init__(self) -> None:
        parsed = urlparse(self.api_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost", "::1", "host.docker.internal"}:
            raise ValueError("CYBERSEG_API_URL debe apuntar a un servicio local (127.0.0.1, localhost, ::1 o host.docker.internal).")
        if self.timeout_seconds < 1:
            raise ValueError("CYBERSEG_TIMEOUT_SECONDS debe ser al menos 1.")
        if not 0 <= self.retry_attempts <= 5:
            raise ValueError("CYBERSEG_HTTP_RETRY_ATTEMPTS debe estar entre 0 y 5.")
        if self.retry_backoff_seconds < 0:
            raise ValueError("CYBERSEG_HTTP_RETRY_BACKOFF_SECONDS no puede ser negativo.")
        object.__setattr__(self, "api_url", self.api_url.rstrip("/"))

    def status(self) -> str:
        health = self._request("/health")
        service = str(health.get("status", "unknown")).upper() if isinstance(health, dict) else "UNKNOWN"
        try:
            state = self._request("/api/engine/state", authenticated=True)
        except CyberSegClientError:
            # Health proves that CyberSeg is online even if the optional engine
            # detail is temporarily busy or its local token needs attention.
            return f"CyberSeg {service}. Estado de captura no disponible temporalmente."
        capture = "activa" if isinstance(state, dict) and state.get("captureEnabled") else "detenida"
        return f"CyberSeg {service}. Captura local {capture}."

    def recent_alerts(self, limit: int = 5) -> str:
        payload = self._request(f"/api/alerts?{urlencode({'limit': min(max(limit, 1), 20)})}")
        if not isinstance(payload, list) or not payload:
            return "CyberSeg no tiene alertas registradas."
        rows = []
        for item in payload[:limit]:
            if not isinstance(item, dict):
                continue
            rows.append(
                f"- [{str(item.get('risk', 'unknown')).upper()}] {item.get('sourceIp', '—')} → "
                f"{item.get('destinationIp', '—')}: {str(item.get('description', 'Sin detalle'))[:180]}"
            )
        return "Alertas recientes de CyberSeg:\n" + "\n".join(rows) if rows else "CyberSeg no devolvió alertas legibles."

    def start_capture(self) -> str:
        state = self._request("/api/engine/start", method="POST", authenticated=True)
        if isinstance(state, dict) and state.get("captureEnabled") is True:
            return "CyberSeg recibió la solicitud de iniciar captura local autorizada."
        raise CyberSegClientError("CyberSeg no confirmó el inicio de captura.")

    def stop_capture(self) -> str:
        state = self._request("/api/engine/stop", method="POST", authenticated=True)
        if isinstance(state, dict) and state.get("captureEnabled") is False:
            return "CyberSeg recibió la solicitud de detener la captura."
        raise CyberSegClientError("CyberSeg no confirmó la detención de captura.")

    def _request(self, path: str, *, method: str = "GET", authenticated: bool = False) -> object:
        headers = {"Accept": "application/json"}
        if authenticated:
            if not self.token:
                raise CyberSegClientError("Falta el token local de CyberSeg en la configuración de JARVIS.")
            headers["X-CyberSeg-Engine-Token"] = self.token
        request = Request(f"{self.api_url}{path}", method=method, headers=headers)
        # GET operations are idempotent, so a short retry improves resilience
        # for direct user requests as well as the background monitor.  State
        # changes are never replayed automatically.
        attempts = self.retry_attempts if method == "GET" else 0
        last_error: Exception | None = None
        for attempt in range(attempts + 1):
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    if not 200 <= response.status < 300:
                        raise CyberSegClientError("CyberSeg respondió con un estado no satisfactorio.")
                    return json.loads(response.read().decode("utf-8"))
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError, CyberSegClientError) as error:
                last_error = error
                if attempt < attempts:
                    time.sleep(self.retry_backoff_seconds * (2**attempt))
        raise CyberSegClientError("CyberSeg local no está disponible o no respondió a tiempo.") from last_error
