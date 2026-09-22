from urllib.parse import quote
from core.error_classifier import safe_error_message
from core.models import TargetContext, ConnectionState, ErrorCategory
from core.security import sanitize_data
from core.url_normalizer import normalize_server_url
from connections.admin_endpoint_resolver import resolve

class FederationDiscovery:
    def __init__(self, client, tokens): self.client, self.tokens = client, tokens
    @staticmethod
    def _values(data, *keys):
        out=[]
        for key in keys:
            value=data.get(key); values=value if isinstance(value,list) else [value] if value else []
            for item in values:
                if str(item) not in out: out.append(str(item))
        return out
    def discover(self, portal, portal_token):
        urls=portal.metadata["urls"]
        payload=self.client.request_json("GET", f"{urls['portal_admin']}/federation/servers", params={"token":portal_token,"f":"json"})
        records=payload.get("servers") or payload.get("items") or []
        if isinstance(records,dict): records=list(records.values())
        results=[]
        for index, raw in enumerate(records):
            record=raw if isinstance(raw,dict) else {"id":str(raw)}
            server_id=str(record.get("id") or record.get("serverId") or f"server-{index+1}")
            detail=dict(record)
            try: detail.update(self.client.request_json("GET", f"{urls['portal_admin']}/federation/servers/{quote(server_id,safe='')}", params={"token":portal_token,"f":"json"}))
            except Exception: pass
            service=detail.get("url") or detail.get("serverUrl") or detail.get("servicesUrl")
            admin=detail.get("adminUrl") or detail.get("adminURL")
            context=TargetContext(server_id, str(detail.get("name") or detail.get("serverName") or f"Federated Server {index+1}"), "server", "enterprise", service_url=str(service or "") or None, registered_admin_url=str(admin or "") or None, roles=self._values(detail,"serverRole","role") or ["FEDERATED_SERVER"], server_functions=self._values(detail,"serverFunction","serverFunctions","function"), federation_state=str(detail.get("federationState") or "federated"), metadata=sanitize_data(detail))
            if not service or not admin:
                context.connection_state=ConnectionState.FAILED; context.error_category=ErrorCategory.SERVER_ADMIN; context.error="Federation record tidak menyediakan Service URL atau Registered Admin URL."; results.append(context); continue
            try:
                service_base=normalize_server_url(str(service))["base"]
                registered=normalize_server_url(str(admin))["admin"]
                context.service_url, context.registered_admin_url=service_base, registered
                server_token=self.tokens.exchange_server_token(urls["sharing_rest"], portal_token, service_base)
                def probe(url):
                    try: self.client.request_json("GET",url,params={"token":server_token.token,"f":"json"}); return True
                    except Exception: return False
                resolved=resolve(service_base,registered,probe)
                context.effective_admin_url, context.connection_route=resolved.effective_admin_url,resolved.route
                root=self.client.request_json("GET",context.effective_admin_url,params={"token":server_token.token,"f":"json"})
                context.version=str(root.get("fullVersion") or root.get("currentVersion") or root.get("version") or "Unknown")
                context.connection_state=ConnectionState.CONNECTED
            except Exception as exc:
                context.connection_state=ConnectionState.FAILED; context.error_category,context.error=safe_error_message(exc,ErrorCategory.SERVER_ADMIN)
            results.append(context)
        return results
