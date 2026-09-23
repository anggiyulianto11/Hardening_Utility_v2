from analysis.evidence_sanitizer import sanitize_evidence


class EvidenceCache:
    def __init__(self, client, token_resolver):
        self.client = client
        self.token_resolver = token_resolver
        self._cache = {}

    def get_json(self, target, relative_path):
        endpoint = f"{target.effective_admin_url.rstrip('/')}/{relative_path.lstrip('/')}"
        return self.get_absolute(target, endpoint)

    def get_absolute(self, target, endpoint):
        key = (target.target_id, endpoint)
        if key not in self._cache:
            token = self.token_resolver(target)
            payload = self.client.request_json(
                "GET", endpoint, params={"token": token, "f": "json"}
            )
            self._cache[key] = {
                "endpoint": endpoint,
                "payload": sanitize_evidence(payload),
            }
        return self._cache[key]

    @property
    def request_count(self):
        return len(self._cache)
