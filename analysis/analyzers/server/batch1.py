from analysis.applicability import TargetScope
from analysis.models import AssessmentResult, AssessmentStatus


class ServerAnalyzerBase:
    scope = TargetScope.ANY_SERVER
    relative_path = "system/properties"

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


class CallbackFunctionsAnalyzer(ServerAnalyzerBase):
    control_id = "AS-B23"

    def analyze(self, target, cache):
        record = cache.get_json(target, self.relative_path)
        payload = record["payload"]
        value = payload.get("callbackFunctionsEnabled", "<default enabled>")
        enabled = True if value == "<default enabled>" else _as_bool(value)
        status = AssessmentStatus.NON_COMPLIANT if enabled else AssessmentStatus.COMPLIANT
        return self.result(target, status, f"callbackFunctionsEnabled={value}", {"endpoint": record["endpoint"], "callbackFunctionsEnabled": value})


class StandardizedQueriesAnalyzer(ServerAnalyzerBase):
    control_id = "AS-B5"

    def analyze(self, target, cache):
        record = cache.get_json(target, self.relative_path)
        payload = record["payload"]
        value = payload.get("standardizedQueries", "<default true>")
        enabled = True if value == "<default true>" else _as_bool(value)
        status = AssessmentStatus.COMPLIANT if enabled else AssessmentStatus.NON_COMPLIANT
        return self.result(target, status, f"standardizedQueries={value}", {"endpoint": record["endpoint"], "standardizedQueries": value})


class FeatureServiceXssBasicAnalyzer(ServerAnalyzerBase):
    control_id = "AS-B14"

    def analyze(self, target, cache):
        record = cache.get_json(target, self.relative_path)
        value = str(record["payload"].get("featureServiceXSSFilter", "<not configured>"))
        status = AssessmentStatus.COMPLIANT if value.lower() in ("input", "inputoutput") else AssessmentStatus.NON_COMPLIANT
        return self.result(target, status, f"featureServiceXSSFilter={value}", {"endpoint": record["endpoint"], "featureServiceXSSFilter": value})


class FeatureServiceXssAdvancedAnalyzer(ServerAnalyzerBase):
    control_id = "AS-A4"

    def analyze(self, target, cache):
        record = cache.get_json(target, self.relative_path)
        value = str(record["payload"].get("featureServiceXSSFilter", "<not configured>"))
        status = AssessmentStatus.COMPLIANT if value.lower() == "inputoutput" else AssessmentStatus.NON_COMPLIANT
        return self.result(target, status, f"featureServiceXSSFilter={value}", {"endpoint": record["endpoint"], "featureServiceXSSFilter": value})


class TokenHttpGetAnalyzer(ServerAnalyzerBase):
    control_id = "AS-B7"
    relative_path = "security/tokens"

    def analyze(self, target, cache):
        record = cache.get_json(target, self.relative_path)
        payload = record["payload"]
        properties = payload.get("properties") or {}
        value = properties.get("allowHttpGet", False)
        enabled = _as_bool(value)
        status = AssessmentStatus.NON_COMPLIANT if enabled else AssessmentStatus.COMPLIANT
        return self.result(target, status, f"allowHttpGet={str(value).lower()}", {"endpoint": record["endpoint"], "allowHttpGet": value})


class ServerLoggingLevelAnalyzer(ServerAnalyzerBase):
    control_id = "AS-B24"
    relative_path = "logs/settings"
    accepted = {"INFO", "FINE", "VERBOSE", "DEBUG"}

    def analyze(self, target, cache):
        record = cache.get_json(target, self.relative_path)
        payload = record["payload"]
        source = payload.get("settings") if isinstance(payload.get("settings"), dict) else payload
        value = str(source.get("logLevel", "<unknown>")).upper()
        status = AssessmentStatus.COMPLIANT if value in self.accepted else AssessmentStatus.NON_COMPLIANT
        return self.result(target, status, f"logLevel={value}", {"endpoint": record["endpoint"], "logLevel": value})


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def build_batch1_analyzers(control_registry):
    return [
        CallbackFunctionsAnalyzer(control_registry),
        StandardizedQueriesAnalyzer(control_registry),
        FeatureServiceXssBasicAnalyzer(control_registry),
        FeatureServiceXssAdvancedAnalyzer(control_registry),
        TokenHttpGetAnalyzer(control_registry),
        ServerLoggingLevelAnalyzer(control_registry),
    ]
