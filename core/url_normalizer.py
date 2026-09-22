from urllib.parse import urlsplit, urlunsplit


def _clean(url: str) -> str:
    value = str(url or "").strip().rstrip("/")
    if not value:
        raise ValueError("URL wajib diisi.")
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL tidak valid.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def normalize_portal_url(url: str) -> dict[str, str]:
    base = _clean(url)
    for suffix in ("/sharing/rest", "/portaladmin"):
        if base.lower().endswith(suffix):
            base = base[: -len(suffix)]
    return {"base": base, "sharing_rest": f"{base}/sharing/rest", "portal_admin": f"{base}/portaladmin", "referer": base}


def normalize_server_url(url: str) -> dict[str, str]:
    value = _clean(url)
    if value.lower().endswith("/admin"):
        base = value[:-6]
    elif value.lower().endswith("/rest/services"):
        base = value[:-14]
    else:
        base = value
    return {"base": base.rstrip("/"), "admin": f"{base.rstrip('/')}/admin", "services": f"{base.rstrip('/')}/rest/services"}
