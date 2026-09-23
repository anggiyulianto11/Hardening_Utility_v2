import json
from core.models import *
from core.security import sanitize_data,sanitize_url
from core.version_normalizer import format_portal_version
from core.url_normalizer import normalize_portal_url,normalize_server_url
from connections.admin_endpoint_resolver import resolve
from connections.connection_registry import ConnectionRegistry
from exports.discovery_export import build_discovery_payload
def test_tataruang_service_first():
    r=resolve("https://tataruang.jakarta.go.id/server","https://ags1.jakarta.go.id:6443/arcgis",lambda u:u=="https://tataruang.jakarta.go.id/server/admin"); assert r.route==ConnectionRoute.SERVICE_URL
def test_fallback(): assert resolve("https://a/server","https://b:6443/arcgis",lambda u:"b:6443" in u).route==ConnectionRoute.REGISTERED_ADMIN_URL
def test_redaction():
    x=sanitize_data({"token":"abc","nested":{"portalSecretKey":"secret","safe":"ok"}}); assert x["token"]=="[REDACTED]" and x["nested"]["portalSecretKey"]=="[REDACTED]" and "abc" not in sanitize_url("https://x?token=abc")
def test_registry():
    r=ConnectionRegistry(); r.add_target(TargetContext("p","Portal","portal","enterprise",connection_state=ConnectionState.CONNECTED)); r.add_target(TargetContext("s","Server","server","enterprise",connection_state=ConnectionState.FAILED)); assert len(r.get_targets())==2 and len(r.get_connected_targets())==1 and len(r.get_failed_targets())==1
def test_result_compat():
    p=TargetContext("p","Portal","portal","enterprise"); s=TargetContext("s","Server","server","enterprise"); r=DiscoveryResult(TargetType.ENTERPRISE,[p,s]); assert r.portal is p and r.servers==[s]
def test_export_safe():
    t=TargetContext("p","Portal","portal","enterprise",metadata={"sharedKey":"secret-value","token":"token-value"}); encoded=json.dumps(build_discovery_payload(DiscoveryResult(TargetType.ENTERPRISE,[t]))); assert "secret-value" not in encoded and "token-value" not in encoded
def test_version(): assert format_portal_version("2025.1")=="2025.1 (Enterprise 11.4)"
def test_urls(): assert normalize_portal_url("https://x/portal")["portal_admin"]=="https://x/portal/portaladmin" and normalize_server_url("https://x/server/admin")["base"]=="https://x/server"
