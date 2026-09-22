from typing import Any
import requests
from core.exceptions import ArcGISConnectionError
from core.security import redact_text, sanitize_url

class ArcGISHttpClient:
    def __init__(self, verify_tls: bool = True, timeout: int = 30):
        self.verify_tls, self.timeout = verify_tls, timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"ArcGIS-Enterprise-Hardening-Utility-v2"})

    def request_json(self, method: str, url: str, *, params=None, data=None) -> dict[str, Any]:
        safe_url = sanitize_url(url)
        try:
            response = self.session.request(method, url, params=params, data=data, verify=self.verify_tls, timeout=self.timeout, headers={"Cache-Control":"no-cache","Pragma":"no-cache"})
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ArcGISConnectionError(f"Request gagal ke {safe_url}: {redact_text(exc)}") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise ArcGISConnectionError(f"Respons dari {safe_url} bukan JSON yang valid.") from exc
        if isinstance(payload, dict) and payload.get("error"):
            error = payload["error"]
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message", "ArcGIS API error") if isinstance(error, dict) else str(error)
            details = error.get("details", []) if isinstance(error, dict) else []
            suffix = ": " + "; ".join(map(str, details)) if details else ""
            raise ArcGISConnectionError((f"ArcGIS {code}: " if code else "") + str(message) + suffix)
        if not isinstance(payload, dict):
            raise ArcGISConnectionError(f"Respons dari {safe_url} tidak berbentuk objek JSON.")
        return payload
