import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from analysis.evidence_sanitizer import sanitize_evidence


class WebEvidenceCache:
    def __init__(self, session, verify_tls=True, timeout=30):
        self.session = session
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._http = {}
        self._cert = {}

    def http(self, url):
        if url not in self._http:
            response = self.session.get(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                verify=self.verify_tls,
                headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
            )
            self._http[url] = sanitize_evidence({
                "requested_url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "redirect_count": len(response.history),
                "headers": dict(response.headers),
            })
        return self._http[url]

    def certificate(self, url):
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port or 443
        key = (host, port)
        if key not in self._cert:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    expires = cert.get("notAfter")
                    expiry = ssl.cert_time_to_seconds(expires) if expires else None
                    days = int((expiry - datetime.now(timezone.utc).timestamp()) / 86400) if expiry else None
                    self._cert[key] = sanitize_evidence({
                        "host": host,
                        "port": port,
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": expires,
                        "subjectAltName": cert.get("subjectAltName"),
                        "days_remaining": days,
                        "trusted_by_client": True,
                    })
        return self._cert[key]

    @property
    def request_count(self):
        return len(self._http) + len(self._cert)
