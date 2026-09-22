from typing import Any
import requests
from core.exceptions import ArcGISConnectionError


class ArcGISHttpClient:
    def __init__(self, verify_tls: bool = True, timeout: int = 30):
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ArcGIS-Enterprise-Hardening-Utility-v2"})

    def request_json(self, method: str, url: str, *, params=None, data=None) -> dict[str, Any]:
        try:
            response = self.session.request(
                method, url, params=params, data=data,
                verify=self.verify_tls, timeout=self.timeout,
                headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ArcGISConnectionError(f"Request gagal ke {url}: {exc}") from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise ArcGISConnectionError(f"Respons dari {url} bukan JSON yang valid.") from exc
        if isinstance(payload, dict) and payload.get("error"):
            error = payload["error"]
            message = error.get("message", "ArcGIS API error") if isinstance(error, dict) else str(error)
            details = error.get("details", []) if isinstance(error, dict) else []
            detail_text = "; ".join(map(str, details))
            raise ArcGISConnectionError(f"{message}" + (f": {detail_text}" if detail_text else ""))
        if not isinstance(payload, dict):
            raise ArcGISConnectionError(f"Respons dari {url} tidak berbentuk objek JSON.")
        return payload
