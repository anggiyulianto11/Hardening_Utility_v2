import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
_REDACTED = "[REDACTED]"
_SENSITIVE = {"password","passwd","token","accesstoken","access_token","refreshtoken","refresh_token","sharedkey","portalsecretkey","webgisservertrustkey","clientsecret","client_secret","secret","credential","credentials","authorization","cookie","setcookie"}

def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9_]", "", str(value).lower())

def is_sensitive_key(key: Any) -> bool:
    k = _key(key)
    return k in _SENSITIVE or k.endswith(("token", "secret", "password"))

def redact_text(text: Any) -> str:
    value = str(text)
    value = re.sub(r"(?i)(token|password|passwd|sharedKey|portalSecretKey|webgisServerTrustKey|clientSecret)=([^&\s]+)", r"\1=[REDACTED]", value)
    return value

def sanitize_url(url: str) -> str:
    try:
        p = urlsplit(str(url))
        q = [(k, _REDACTED if is_sensitive_key(k) else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))
    except Exception:
        return redact_text(url)

def sanitize_data(value: Any, key: Any = None) -> Any:
    if key is not None and is_sensitive_key(key):
        return _REDACTED
    if isinstance(value, dict):
        return {str(k): sanitize_data(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_data(v) for v in value]
    if isinstance(value, tuple):
        return tuple(sanitize_data(v) for v in value)
    return redact_text(value) if isinstance(value, str) else value
