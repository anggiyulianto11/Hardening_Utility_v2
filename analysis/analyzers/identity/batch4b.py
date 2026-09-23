from analysis.applicability import TargetScope
from analysis.models import AssessmentResult, AssessmentStatus


class IdentityAnalyzerBase:
    scope = TargetScope.PORTAL

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


class AdministratorMfaAnalyzer(IdentityAnalyzerBase):
    control_id = "IA-B1"

    def analyze(self, target, members):
        users = [u for u in members["users"] if not u["disabled"]]
        admins = [u for u in users if u["role"] == "org_admin"]
        local = [u for u in admins if str(u["provider"]).lower() == "arcgis"]
        external = [u for u in admins if str(u["provider"]).lower() != "arcgis"]
        local_missing = [u for u in local if u["mfa_enabled"] is not True]
        local_unknown = [u for u in local if u["mfa_enabled"] is None]
        if not admins:
            status = AssessmentStatus.NOT_ASSESSABLE
        elif local_missing:
            status = AssessmentStatus.NON_COMPLIANT
        elif external:
            status = AssessmentStatus.NEEDS_REVIEW
        else:
            status = AssessmentStatus.COMPLIANT
        return self.result(target, status,
            f"active_admins={len(admins)}; local_admins={len(local)}; local_without_mfa={len(local_missing)}; external_idp_admins={len(external)}",
            {"source": members["endpoint"], "active_admins": len(admins), "local_without_mfa": [u["account_ref"] for u in local_missing], "external_idp_admins": [u["account_ref"] for u in external], "local_mfa_unknown": [u["account_ref"] for u in local_unknown]})


class AllUsersMfaAnalyzer(IdentityAnalyzerBase):
    control_id = "IA-A3"

    def analyze(self, target, members):
        users = [u for u in members["users"] if not u["disabled"]]
        local = [u for u in users if str(u["provider"]).lower() == "arcgis"]
        external = [u for u in users if str(u["provider"]).lower() != "arcgis"]
        local_missing = [u for u in local if u["mfa_enabled"] is not True]
        if local_missing:
            status = AssessmentStatus.NON_COMPLIANT
        elif external:
            status = AssessmentStatus.NEEDS_REVIEW
        elif users:
            status = AssessmentStatus.COMPLIANT
        else:
            status = AssessmentStatus.NOT_ASSESSABLE
        return self.result(target, status,
            f"active_users={len(users)}; local_users={len(local)}; local_without_mfa={len(local_missing)}; external_idp_users={len(external)}",
            {"source": members["endpoint"], "active_users": len(users), "local_without_mfa": [u["account_ref"] for u in local_missing], "external_idp_count": len(external)})


class DefaultRoleAnalyzer(IdentityAnalyzerBase):
    control_id = "IA-B13"

    def analyze(self, target, members):
        urls = target.metadata["urls"]
        # portal self is already cached by API evidence cache; the orchestrator injects it.
        portal_self = members.get("portal_self") or {}
        role = portal_self.get("defaultUserRole") or portal_self.get("defaultRole") or portal_self.get("defaultUserRoleId")
        if role is None:
            status = AssessmentStatus.NOT_ASSESSABLE
            shown = "<not published>"
        else:
            shown = str(role)
            status = AssessmentStatus.COMPLIANT if any(x in shown.lower() for x in ("viewer", "org_user")) else AssessmentStatus.NON_COMPLIANT
        return self.result(target, status, f"default_member_role={shown}", {"source": f"{urls['sharing_rest']}/portals/self", "default_member_role": shown})


class CustomRolesAnalyzer(IdentityAnalyzerBase):
    control_id = "IA-A1"

    def analyze(self, target, members):
        users = [u for u in members["users"] if not u["disabled"]]
        custom = [u for u in users if u.get("role_id") and u["role"] not in ("org_admin", "org_publisher", "org_user")]
        status = AssessmentStatus.NEEDS_REVIEW if custom else AssessmentStatus.COMPLIANT
        role_ids = sorted({str(u["role_id"]) for u in custom if u.get("role_id")})
        return self.result(target, status,
            f"active_users={len(users)}; users_with_custom_role={len(custom)}; custom_role_ids={len(role_ids)}",
            {"source": members["endpoint"], "custom_role_ids": role_ids, "account_refs": [u["account_ref"] for u in custom]})


def build_batch4b_analyzers(control_registry):
    return [AdministratorMfaAnalyzer(control_registry), AllUsersMfaAnalyzer(control_registry), DefaultRoleAnalyzer(control_registry), CustomRolesAnalyzer(control_registry)]
