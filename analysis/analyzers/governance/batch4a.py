from urllib.parse import urlsplit

from analysis.applicability import TargetScope
from analysis.models import AssessmentResult, AssessmentStatus


class GovernanceAnalyzerBase:
    def __init__(self, control_registry):
        self.definition = control_registry.get_control_by_id(self.control_id)
        if self.definition is None:
            raise ValueError(f"Control {self.control_id} tidak tersedia di katalog.")

    def result(self, target, status, current, evidence):
        d = self.definition
        return AssessmentResult(
            control_id=d.control_id,
            control_name=d.control_name,
            target_id=target.target_id,
            target_name=target.target_name,
            component_type=target.component_type,
            profile=d.profile,
            area=d.area,
            verification_method=d.verification_method,
            implementation_side=d.implementation_side,
            status=status,
            security_risk=d.security_risk,
            privacy_risk=d.privacy_risk,
            current_condition=current,
            expected_condition=d.expected_condition,
            recommendation=d.recommendation,
            evidence=evidence,
            implementation_supported=False,
            implementation_readiness=d.implementation_readiness,
            operational_impact=d.operational_impact,
            recovery_plan=d.recovery_plan,
        )


class PrimarySiteAdministratorAnalyzer(GovernanceAnalyzerBase):
    control_id = "AS-B2"
    scope = TargetScope.ANY_SERVER

    def analyze(self, target, api_cache):
        record = api_cache.get_json(target, "security/psa")
        value = record["payload"].get("disabled")
        disabled = _as_bool(value)
        status = AssessmentStatus.COMPLIANT if disabled else AssessmentStatus.NON_COMPLIANT
        return self.result(
            target,
            status,
            f"Primary Site Administrator disabled={str(disabled).lower()}",
            {"endpoint": record["endpoint"], "disabled": disabled},
        )


class OrganizationWebhooksAnalyzer(GovernanceAnalyzerBase):
    control_id = "DR-B1"
    scope = TargetScope.PORTAL

    def analyze(self, target, api_cache):
        urls = target.metadata["urls"]
        endpoint = f"{urls['sharing_rest']}/portals/{target.target_id}/webhooks"
        record = api_cache.get_absolute(target, endpoint)
        payload = record["payload"]
        webhooks = payload.get("webhooks") or payload.get("items") or payload.get("data") or []
        if isinstance(webhooks, dict):
            webhooks = list(webhooks.values())
        summaries = []
        insecure = 0
        inactive = 0
        for item in webhooks:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or item.get("payloadUrl") or item.get("hookUrl") or ""
            active = item.get("active", item.get("status", True))
            if url and urlsplit(str(url)).scheme.lower() != "https":
                insecure += 1
            if not _as_bool(active):
                inactive += 1
            summaries.append({
                "name": item.get("name") or item.get("id") or "webhook",
                "receiver_scheme": urlsplit(str(url)).scheme.lower() if url else "unknown",
                "active": _as_bool(active),
            })
        if insecure:
            status = AssessmentStatus.NON_COMPLIANT
        elif not summaries:
            status = AssessmentStatus.NEEDS_REVIEW
        elif inactive:
            status = AssessmentStatus.WARNING
        else:
            status = AssessmentStatus.COMPLIANT
        return self.result(
            target,
            status,
            f"organization_webhooks={len(summaries)}; insecure_receivers={insecure}; inactive={inactive}",
            {"endpoint": record["endpoint"], "summary": summaries},
        )


class UtilityServiceDependenciesAnalyzer(GovernanceAnalyzerBase):
    control_id = "AS-A1"
    scope = TargetScope.PORTAL

    def analyze(self, target, api_cache):
        urls = target.metadata["urls"]
        endpoint = f"{urls['sharing_rest']}/portals/self"
        record = api_cache.get_absolute(target, endpoint)
        helper = record["payload"].get("helperServices") or {}
        portal_host = urlsplit(target.service_url).hostname
        inventory = []
        insecure = 0
        external = 0
        for service_name, raw in helper.items():
            entries = raw if isinstance(raw, list) else [raw]
            for entry in entries:
                if isinstance(entry, dict):
                    value = entry.get("url") or entry.get("serviceUrl") or ""
                else:
                    value = str(entry or "")
                if not value:
                    continue
                parts = urlsplit(value)
                is_external = bool(parts.hostname and parts.hostname != portal_host)
                if parts.scheme.lower() != "https":
                    insecure += 1
                if is_external:
                    external += 1
                inventory.append({
                    "service": service_name,
                    "url": value,
                    "scheme": parts.scheme.lower(),
                    "host": parts.hostname,
                    "external": is_external,
                })
        if insecure:
            status = AssessmentStatus.NON_COMPLIANT
        elif external:
            status = AssessmentStatus.NEEDS_REVIEW
        elif inventory:
            status = AssessmentStatus.COMPLIANT
        else:
            status = AssessmentStatus.NOT_ASSESSABLE
        return self.result(
            target,
            status,
            f"utility_services={len(inventory)}; external={external}; insecure_http={insecure}",
            {"endpoint": record["endpoint"], "utility_services": inventory},
        )


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on", "active", "enabled")


def build_batch4a_analyzers(control_registry):
    return [
        PrimarySiteAdministratorAnalyzer(control_registry),
        OrganizationWebhooksAnalyzer(control_registry),
        UtilityServiceDependenciesAnalyzer(control_registry),
    ]
