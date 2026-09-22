from core.models import TargetContext, ConnectionState, ConnectionRoute
from core.security import sanitize_data
from core.url_normalizer import normalize_server_url
class StandaloneServerConnection:
    def __init__(self,client,tokens): self.client,self.tokens=client,tokens
    def connect(self,server_url,username,password):
        urls=normalize_server_url(server_url)
        token=self.tokens.login_standalone_server(urls["admin"],username,password)
        root=self.client.request_json("GET",urls["admin"],params={"token":token.token,"f":"json"})
        return TargetContext(urls["base"],"Standalone ArcGIS Server","server","standalone_server",service_url=urls["services"],registered_admin_url=urls["admin"],effective_admin_url=urls["admin"],version=str(root.get("fullVersion") or root.get("currentVersion") or root.get("version") or "Unknown"),roles=["STANDALONE_SERVER"],federation_state="standalone",connection_state=ConnectionState.CONNECTED,connection_route=ConnectionRoute.DIRECT_ADMIN_URL,metadata=sanitize_data(root))
