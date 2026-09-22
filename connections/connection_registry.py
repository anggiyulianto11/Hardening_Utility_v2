from core.models import DiscoveryResult, TargetType
from connections.http_client import ArcGISHttpClient
from connections.token_manager import TokenManager
from connections.portal_connection import PortalConnection
from connections.federation_discovery import FederationDiscovery
from connections.server_connection import StandaloneServerConnection


class ConnectionRegistry:
    def __init__(self, verify_tls: bool = True, timeout: int = 30):
        self.client = ArcGISHttpClient(verify_tls=verify_tls, timeout=timeout)
        self.tokens = TokenManager(self.client)

    def connect_enterprise(self, portal_url: str, username: str, password: str) -> DiscoveryResult:
        portal, portal_token = PortalConnection(self.client, self.tokens).connect(
            portal_url, username, password
        )
        servers = FederationDiscovery(self.client, self.tokens).discover(portal, portal_token.token)
        return DiscoveryResult(target_type=TargetType.ENTERPRISE, portal=portal, servers=servers)

    def connect_standalone(self, server_url: str, username: str, password: str) -> DiscoveryResult:
        server = StandaloneServerConnection(self.client, self.tokens).connect(
            server_url, username, password
        )
        return DiscoveryResult(target_type=TargetType.STANDALONE_SERVER, servers=[server])
