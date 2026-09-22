import time
from dataclasses import dataclass
from core.exceptions import ArcGISConnectionError

@dataclass
class TokenRecord:
    token: str
    expires_ms: int
    def valid(self, margin_seconds: int = 60) -> bool:
        return self.expires_ms > int((time.time() + margin_seconds) * 1000)

class TokenManager:
    def __init__(self, client):
        self.client = client
        self.portal_token = None
        self.server_tokens = {}

    @staticmethod
    def _record(payload):
        token = payload.get("token")
        if not token:
            raise ArcGISConnectionError("Token tidak tersedia pada respons autentikasi.")
        return TokenRecord(str(token), int(payload.get("expires") or (time.time() + 3600) * 1000))

    def login_portal(self, sharing_rest, username, password, referer):
        payload = self.client.request_json("POST", f"{sharing_rest}/generateToken", data={"username":username,"password":password,"client":"referer","referer":referer,"expiration":"60","f":"json"})
        self.portal_token = self._record(payload)
        return self.portal_token

    def exchange_server_token(self, sharing_rest, portal_token, server_url):
        record = self._record(self.client.request_json("POST", f"{sharing_rest}/generateToken", data={"token":portal_token,"serverUrl":server_url,"f":"json"}))
        self.server_tokens[server_url] = record
        return record

    def login_standalone_server(self, admin_url, username, password):
        return self._record(self.client.request_json("POST", f"{admin_url}/generateToken", data={"username":username,"password":password,"client":"requestip","expiration":"60","f":"json"}))
