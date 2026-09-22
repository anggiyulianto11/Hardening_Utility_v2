import requests
from core.models import ErrorCategory
from core.security import redact_text

def classify_error(exc: BaseException, default: ErrorCategory = ErrorCategory.UNKNOWN) -> ErrorCategory:
    text = str(exc).lower()
    if isinstance(exc, requests.exceptions.SSLError) or "certificate verify" in text or "ssl" in text:
        return ErrorCategory.TLS
    if isinstance(exc, requests.exceptions.Timeout) or "timeout" in text or "timed out" in text:
        return ErrorCategory.TIMEOUT
    if "498" in text or "invalid token" in text or "token expired" in text:
        return ErrorCategory.AUTHENTICATION
    if "499" in text or "token required" in text or "forbidden" in text or "permission" in text:
        return ErrorCategory.AUTHORIZATION
    if isinstance(exc, requests.exceptions.ConnectionError) or "name resolution" in text or "failed to establish" in text:
        return ErrorCategory.CONNECTION
    if "json" in text or "invalid response" in text:
        return ErrorCategory.INVALID_RESPONSE
    return default

def safe_error_message(exc: BaseException, default: ErrorCategory = ErrorCategory.UNKNOWN):
    return classify_error(exc, default), redact_text(exc)
