from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cyberseg_engine.models import DetectionAlert


class AlertPublisher:
    def __init__(self, api_url: str, token: str, timeout_seconds: int = 3) -> None:
        self.api_url, self.token, self.timeout_seconds = api_url.rstrip("/"), token, timeout_seconds

    def publish(self, alert: DetectionAlert) -> None:
        request = Request(
            f"{self.api_url}/api/alerts", data=json.dumps(alert.payload()).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "X-CyberSeg-Engine-Token": self.token},
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                if not 200 <= response.status < 300:
                    raise ConnectionError(f"CyberSeg API respondió {response.status}.")
        except (HTTPError, URLError, TimeoutError) as error:
            raise ConnectionError("No se pudo publicar la alerta en la API local de CyberSeg.") from error
