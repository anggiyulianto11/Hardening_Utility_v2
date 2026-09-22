from dataclasses import dataclass
from core.models import ConnectionRoute
@dataclass(frozen=True)
class ResolvedAdminEndpoint:
    effective_admin_url: str
    route: ConnectionRoute

def _admin(url):
    clean = str(url or "").rstrip("/")
    return clean if clean.lower().endswith("/admin") else f"{clean}/admin"

def resolve(service_url, registered_admin_url, probe):
    service_admin = _admin(service_url)
    if probe(service_admin):
        return ResolvedAdminEndpoint(service_admin, ConnectionRoute.SERVICE_URL)
    registered_admin = _admin(registered_admin_url)
    if probe(registered_admin):
        return ResolvedAdminEndpoint(registered_admin, ConnectionRoute.REGISTERED_ADMIN_URL)
    raise RuntimeError("Service URL dan Registered Admin URL tidak dapat digunakan.")
