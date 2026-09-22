from core.models import DiscoveryResult, TargetType, ConnectionState
from connections.http_client import ArcGISHttpClient
from connections.token_manager import TokenManager
from connections.portal_connection import PortalConnection
from connections.federation_discovery import FederationDiscovery
from connections.server_connection import StandaloneServerConnection
class ConnectionRegistry:
    def __init__(self,verify_tls=True,timeout=30):
        self.client=ArcGISHttpClient(verify_tls,timeout); self.tokens=TokenManager(self.client); self._targets=[]
    def add_target(self,target): self._targets=[x for x in self._targets if x.target_id!=target.target_id]+[target]
    def get_targets(self): return list(self._targets)
    def get_connected_targets(self): return [x for x in self._targets if x.connection_state==ConnectionState.CONNECTED]
    def get_failed_targets(self): return [x for x in self._targets if x.connection_state==ConnectionState.FAILED]
    def connect_enterprise(self,portal_url,username,password):
        self._targets.clear(); portal,token=PortalConnection(self.client,self.tokens).connect(portal_url,username,password); self.add_target(portal)
        for server in FederationDiscovery(self.client,self.tokens).discover(portal,token.token): self.add_target(server)
        return DiscoveryResult(TargetType.ENTERPRISE,self.get_targets())
    def connect_standalone(self,server_url,username,password):
        self._targets.clear(); self.add_target(StandaloneServerConnection(self.client,self.tokens).connect(server_url,username,password)); return DiscoveryResult(TargetType.STANDALONE_SERVER,self.get_targets())
