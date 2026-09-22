from urllib.parse import urlparse, urlunparse


def _https_url(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise ValueError("URL harus lengkap dan menggunakan HTTPS.")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def normalize_portal_url(value: str) -> dict[str, str]:
    url = _https_url(value)
    path = urlparse(url).path.rstrip("/")
    lower = path.lower()
    for suffix in ("/portaladmin", "/sharing/rest", "/home"):
        if lower.endswith(suffix):
            path = path[:-len(suffix)]
            break
    parsed = urlparse(url)
    base = urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "", "")).rstrip("/")
    return {
        "base": base,
        "sharing_rest": f"{base}/sharing/rest",
        "portal_admin": f"{base}/portaladmin",
        "referer": base,
    }


def normalize_server_url(value: str) -> dict[str, str]:
    url = _https_url(value)
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    lower = path.lower()
    for suffix in ("/admin", "/rest/services", "/rest"):
        if lower.endswith(suffix):
            path = path[:-len(suffix)]
            break
    base = urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/"), "", "", "")).rstrip("/")
    return {"base": base, "admin": f"{base}/admin", "services": f"{base}/rest/services"}
