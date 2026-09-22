from urllib.parse import quote
from core.models import TargetContext, ConnectionState
from core.url_normalizer import normalize_server_url
from connections.admin_endpoint_resolver import resolve
from connections.http_client import ArcGISHttpClient
from connections.token_manager import TokenManager


class FederationDiscovery:
    def __init__(self, client: ArcGISHttpClient, tokens: TokenManager):
        self.client = client
        self.tokens = tokens

    @staticmethod
    def _roles(data: dict) -> list[str]:
        values = []
        for key in ("serverRole", "serverFunction", "role", "function"):
            value = data.get(key)
            if value and value not in values:
                if isinstance(value, list):
                    values.extend(str(item) for item in value if str(item) not in values)
                else:
                    values.append(str(value))
        return values or ["FEDERATED_SERVER"]

    def discover(self, portal: TargetContext, portal_token: str) -> list[TargetContext]:
        urls = portal.metadata["urls"]
        payload = self.client.request_json(
            "GET", f"{urls['portal_admin']}/federation/servers",
            params={"token": portal_token, "f": "json"},
        )
        records = payload.get("servers") or payload.get("items") or []
        if isinstance(records, dict):
            records = list(records.values())
        results = []
        for index, record in enumerate(records):
            record = record if isinstance(record, dict) else {"id": str(record)}
            server_id = str(record.get("id") or record.get("serverId") or f"server-{index+1}")
            detail = dict(record)
            try:
                detail_payload = self.client.request_json(
                    "GET", f"{urls['portal_admin']}/federation/servers/{quote(server_id, safe='')}",
                    params={"token": portal_token, "f": "json"},
                )
                detail.update(detail_payload)
            except Exception:
                pass
            service_url = detail.get("url") or detail.get("serverUrl") or detail.get("servicesUrl")
            registered_admin_url = detail.get("adminUrl") or detail.get("adminURL")
            context = TargetContext(
                target_id=server_id,
                target_name=str(detail.get("name") or detail.get("serverName") or f"Federated Server {index+1}"),
                component_type="server", deployment_mode="enterprise",
                service_url=str(service_url or "") or None,
                registered_admin_url=str(registered_admin_url or "") or None,
                roles=self._roles(detail), federation_state="federated", metadata=detail,
            )
            if not service_url:
                context.connection_state = ConnectionState.FAILED
                context.error = "Federation record tidak menyediakan adminUrl atau services URL."
                results.append(context)
                continue
            try:
                service_normalized = normalize_server_url(str(service_url))
                registered_normalized = (
                    normalize_server_url(str(registered_admin_url))
                    if registered_admin_url else None
                )
                context.service_url = service_normalized["base"]
                context.registered_admin_url = (
                    registered_normalized["base"] if registered_normalized else None
                )
                server_token = self.tokens.exchange_server_token(
                    urls["sharing_rest"], portal_token, str(service_url)
                )

                def probe(endpoint: str) -> bool:
                    try:
                        self.client.request_json(
                            "GET", endpoint,
                            params={"token": server_token.token, "f": "json"},
                        )
                        return True
                    except Exception:
                        return False

                resolved = resolve(
                    context.service_url,
                    context.registered_admin_url or context.service_url,
                    probe,
                )
                context.effective_admin_url = resolved.effective_admin_url
                context.connection_route = resolved.route
                root = self.client.request_json(
                    "GET", context.effective_admin_url,
                    params={"token": server_token.token, "f": "json"},
                )
                context.version = str(root.get("currentVersion") or root.get("version") or "Unknown")
                context.connection_state = ConnectionState.CONNECTED
            except Exception as exc:
                context.connection_state = ConnectionState.FAILED
                context.error = str(exc)
            results.append(context)
        return results
