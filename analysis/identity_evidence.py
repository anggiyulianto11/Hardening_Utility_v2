import hashlib

from analysis.evidence_sanitizer import sanitize_evidence


class PortalMemberCollector:
    def __init__(self, client, token_resolver, page_size=100):
        self.client = client
        self.token_resolver = token_resolver
        self.page_size = min(max(int(page_size), 1), 100)
        self._cache = {}
        self.request_count = 0

    def collect(self, portal_target):
        if portal_target.target_id in self._cache:
            return self._cache[portal_target.target_id]
        urls = portal_target.metadata["urls"]
        endpoint = f"{urls['sharing_rest']}/portals/{portal_target.target_id}/users"
        token = self.token_resolver(portal_target)
        start = 1
        users = []
        seen = set()
        while start and start > 0:
            payload = self.client.request_json(
                "GET",
                endpoint,
                params={
                    "token": token,
                    "f": "json",
                    "start": start,
                    "num": self.page_size,
                    "sortField": "username",
                    "sortOrder": "asc",
                },
            )
            self.request_count += 1
            page = payload.get("users") or payload.get("results") or []
            for raw in page:
                if not isinstance(raw, dict):
                    continue
                username = str(raw.get("username") or "")
                key = username.lower()
                if not username or key in seen:
                    continue
                seen.add(key)
                users.append(self._minimal_user(raw))
            next_start = payload.get("nextStart", -1)
            try:
                next_start = int(next_start)
            except (TypeError, ValueError):
                next_start = -1
            if next_start <= 0 or next_start == start:
                break
            start = next_start
        result = sanitize_evidence({
            "endpoint": endpoint,
            "total": len(users),
            "users": users,
        })
        self._cache[portal_target.target_id] = result
        return result

    @staticmethod
    def _minimal_user(raw):
        username = str(raw.get("username") or "")
        return {
            "account_ref": hashlib.sha256(username.lower().encode("utf-8")).hexdigest()[:12],
            "provider": raw.get("provider") or "unknown",
            "role": raw.get("role") or "unknown",
            "role_id": raw.get("roleId") or raw.get("roleID"),
            "disabled": bool(raw.get("disabled", False)),
            "mfa_enabled": raw.get("mfaEnabled"),
            "last_login": raw.get("lastLogin"),
            "user_type": raw.get("userLicenseTypeId") or raw.get("userType"),
        }
