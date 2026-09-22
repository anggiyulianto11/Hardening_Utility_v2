from core.models import TargetContext, ConnectionState, ConnectionRoute
from core.security import sanitize_data
from core.url_normalizer import normalize_portal_url
from core.version_normalizer import format_portal_version


class PortalConnection:
    def __init__(self, client, tokens):
        self.client = client
        self.tokens = tokens

    def connect(self, portal_url, username, password):
        urls = normalize_portal_url(portal_url)
        token = self.tokens.login_portal(
            urls["sharing_rest"], username, password, urls["referer"]
        )
        portal_self = self.client.request_json(
            "GET",
            f"{urls['sharing_rest']}/portals/self",
            params={"token": token.token, "f": "json"},
        )
        portal_root = self.client.request_json(
            "GET",
            urls["portal_admin"],
            params={"token": token.token, "f": "json"},
        )

        portal_self_version = portal_self.get("currentVersion") or portal_self.get("version")
        portal_admin_version = portal_root.get("currentVersion") or portal_root.get("version")
        full_version = portal_self.get("fullVersion") or portal_root.get("fullVersion")

        context = TargetContext(
            target_id=str(portal_self.get("id") or "portal"),
            target_name=str(
                portal_self.get("name")
                or portal_self.get("portalName")
                or "ArcGIS Enterprise Portal"
            ),
            component_type="portal",
            deployment_mode="enterprise",
            service_url=urls["base"],
            registered_admin_url=urls["portal_admin"],
            effective_admin_url=urls["portal_admin"],
            version=format_portal_version(
                portal_self_version=portal_self_version,
                portal_admin_version=portal_admin_version,
                full_version=full_version,
            ),
            federation_state="portal",
            connection_state=ConnectionState.CONNECTED,
            connection_route=ConnectionRoute.DIRECT_ADMIN_URL,
            metadata=sanitize_data({
                "urls": urls,
                "portal_self_version": portal_self_version,
                "portal_admin_version": portal_admin_version,
                "full_version": full_version,
            }),
        )
        return context, token
