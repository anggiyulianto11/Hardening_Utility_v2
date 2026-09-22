from core.models import TargetContext, ConnectionState
from core.url_normalizer import normalize_portal_url
from connections.http_client import ArcGISHttpClient
from connections.token_manager import TokenManager


class PortalConnection:
    def __init__(self, client: ArcGISHttpClient, tokens: TokenManager):
        self.client = client
        self.tokens = tokens

    def connect(self, portal_url: str, username: str, password: str):
        urls = normalize_portal_url(portal_url)
        token = self.tokens.login_portal(
            urls["sharing_rest"], username, password, urls["referer"]
        )
        portal_self = self.client.request_json(
            "GET", f"{urls['sharing_rest']}/portals/self",
            params={"token": token.token, "f": "json"},
        )
        portal_root = self.client.request_json(
            "GET", urls["portal_admin"],
            params={"token": token.token, "f": "json"},
        )
        context = TargetContext(
            target_id=str(portal_self.get("id") or "portal"),
            target_name=str(portal_self.get("name") or portal_self.get("portalName") or "ArcGIS Enterprise Portal"),
            component_type="portal", deployment_mode="enterprise",
            service_url=urls["base"],
            registered_admin_url=urls["portal_admin"], effective_admin_url=urls["portal_admin"],
            version=str(portal_root.get("currentVersion") or portal_self.get("currentVersion") or "Unknown"),
            federation_state="portal", connection_state=ConnectionState.CONNECTED,
            metadata={"urls": urls},
        )
        return context, token
