from core.models import TargetContext, ConnectionState
from core.url_normalizer import normalize_server_url
from connections.http_client import ArcGISHttpClient
from connections.token_manager import TokenManager


class StandaloneServerConnection:
    def __init__(self, client: ArcGISHttpClient, tokens: TokenManager):
        self.client = client
        self.tokens = tokens

    def connect(self, server_url: str, username: str, password: str) -> TargetContext:
        urls = normalize_server_url(server_url)
        token = self.tokens.login_standalone_server(urls["admin"], username, password)
        root = self.client.request_json(
            "GET", urls["admin"], params={"token": token.token, "f": "json"}
        )
        return TargetContext(
            target_id=urls["base"], target_name="Standalone ArcGIS Server",
            component_type="server", deployment_mode="standalone_server",
            service_url=urls["services"],
            registered_admin_url=urls["admin"], effective_admin_url=urls["admin"],
            version=str(root.get("currentVersion") or root.get("version") or "Unknown"),
            roles=["STANDALONE_SERVER"], federation_state="standalone",
            connection_state=ConnectionState.CONNECTED,
        )
