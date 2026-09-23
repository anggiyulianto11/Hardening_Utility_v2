from analysis.evidence_sanitizer import sanitize_evidence
from analysis.models import AssessmentResult, AssessmentStatus


class CallbackFunctionsAnalyzer:
    CONTROL_ID = "AS-B23"

    def __init__(self, client, control_registry):
        self.client = client
        self.definition = control_registry.get_control_by_id(self.CONTROL_ID)
        if self.definition is None:
            raise ValueError(f"Control {self.CONTROL_ID} tidak tersedia di katalog.")

    @staticmethod
    def _effective_value(payload):
        if "callbackFunctionsEnabled" not in payload:
            return True, "default enabled"
        value = payload.get("callbackFunctionsEnabled")
        if isinstance(value, str):
            enabled = value.strip().lower() not in ("false", "0", "no", "off")
        else:
            enabled = bool(value)
        return enabled, str(value).lower()

    def analyze(self, target, token):
        endpoint = f"{target.effective_admin_url.rstrip('/')}/system/properties"
        payload = self.client.request_json(
            "GET", endpoint, params={"token": token, "f": "json"}
        )
        enabled, display_value = self._effective_value(payload)
        status = (
            AssessmentStatus.NON_COMPLIANT
            if enabled
            else AssessmentStatus.COMPLIANT
        )
        current = (
            "callbackFunctionsEnabled=<default enabled>"
            if "callbackFunctionsEnabled" not in payload
            else f"callbackFunctionsEnabled={display_value}"
        )
        return AssessmentResult(
            control_id=self.definition.control_id,
            control_name=self.definition.control_name,
            target_id=target.target_id,
            target_name=target.target_name,
            component_type=target.component_type,
            profile=self.definition.profile,
            area=self.definition.area,
            verification_method=self.definition.verification_method,
            implementation_side=self.definition.implementation_side,
            status=status,
            security_risk=self.definition.security_risk,
            privacy_risk=self.definition.privacy_risk,
            current_condition=current,
            expected_condition=self.definition.expected_condition,
            recommendation=self.definition.recommendation,
            evidence=sanitize_evidence(
                {
                    "endpoint": endpoint,
                    "callbackFunctionsEnabled": payload.get(
                        "callbackFunctionsEnabled", "<default enabled>"
                    ),
                }
            ),
            implementation_supported=False,
            implementation_readiness=self.definition.implementation_readiness,
            operational_impact=self.definition.operational_impact,
            recovery_plan=self.definition.recovery_plan,
        )
