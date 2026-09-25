from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class RegisteredMachinesResult:
    names: list[str]
    endpoint: str
    error: str = ""

    @property
    def full_text(self):
        if self.names:
            return ", ".join(self.names)
        return "Unavailable" if self.error else "-"


def machines_endpoint(target):
    admin_url = str(
        getattr(target, "effective_admin_url", "")
        or getattr(target, "registered_admin_url", "")
        or ""
    ).rstrip("/")
    return f"{admin_url}/machines" if admin_url else ""


def _identity(value):
    """Return strict site identity: host:port plus first application context."""
    parsed = urlparse(str(value or "").strip())
    host = (parsed.hostname or "").lower()
    port = parsed.port
    authority = f"{host}:{port}" if port else host
    segments = [part.lower() for part in parsed.path.split("/") if part]
    while segments and segments[-1] in {"admin", "portaladmin", "machines"}:
        segments.pop()
    context = segments[0] if segments else ""
    return authority, context


def _target_identities(target):
    values = (
        getattr(target, "service_url", ""),
        getattr(target, "registered_admin_url", ""),
        getattr(target, "effective_admin_url", ""),
    )
    return {_identity(value) for value in values if value}


def _record_identities(key, record):
    values = [key]
    for attr in (
        "service_url", "site_url", "audience_url", "admin_url",
        "registered_admin_url", "effective_admin_url", "url",
    ):
        value = getattr(record, attr, "")
        if value:
            values.append(value)
    return {_identity(value) for value in values if value}


def _strict_server_token(registry, target):
    tokens = getattr(registry, "tokens", None)
    records = getattr(tokens, "server_tokens", {}) if tokens else {}
    records = records or {}

    target_id = str(getattr(target, "target_id", "") or "")
    direct = records.get(target_id)
    if direct and direct.valid():
        return direct.token

    identities = _target_identities(target)
    matches = []
    for key, record in records.items():
        if not record or not record.valid():
            continue
        if identities.intersection(_record_identities(key, record)):
            matches.append(record.token)

    # Fail closed. A token is accepted only when exactly one site-specific match
    # exists. Never try a token belonging to another ArcGIS Server site.
    unique = list(dict.fromkeys(matches))
    return unique[0] if len(unique) == 1 else ""


def _token_for_target(registry, target):
    tokens = getattr(registry, "tokens", None)
    if str(getattr(target, "component_type", "")).lower() == "portal":
        record = getattr(tokens, "portal_token", None) if tokens else None
        return record.token if record and record.valid() else ""
    return _strict_server_token(registry, target)


def _machine_name(value):
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, dict):
        return ""
    for key in (
        "machineName", "machinename", "name", "machine", "hostName",
        "hostname", "serverName", "server",
    ):
        candidate = value.get(key)
        if candidate:
            return str(candidate).strip()
    return ""


def extract_machine_names(payload):
    candidates = []
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        for key in ("machines", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                candidates = value
                break
        if not candidates and any(
            key in payload for key in ("machineName", "machinename", "name")
        ):
            candidates = [payload]

    names, seen = [], set()
    for item in candidates:
        name = _machine_name(item)
        normalized = name.upper()
        if name and normalized not in seen:
            seen.add(normalized)
            names.append(name)
    return names


def read_registered_machines(registry, target):
    endpoint = machines_endpoint(target)
    if not endpoint:
        return RegisteredMachinesResult([], "", "Admin URL tidak tersedia")

    token = _token_for_target(registry, target)
    if not token:
        return RegisteredMachinesResult(
            [], endpoint,
            "Server-token khusus site tidak ditemukan atau pemetaan token ambigu",
        )

    client = getattr(registry, "client", None)
    if client is None:
        return RegisteredMachinesResult([], endpoint, "HTTP client tidak tersedia")

    try:
        payload = client.request_json(
            "GET", endpoint, params={"token": token, "f": "json"}
        )
        names = extract_machine_names(payload)
        if not names:
            return RegisteredMachinesResult(
                [], endpoint, "Endpoint tidak mengembalikan nama machine"
            )
        return RegisteredMachinesResult(names, endpoint)
    except Exception as exc:
        return RegisteredMachinesResult([], endpoint, str(exc))
