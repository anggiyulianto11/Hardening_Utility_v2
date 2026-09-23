from urllib.parse import urlsplit

from analysis.applicability import TargetScope
from analysis.models import AssessmentResult, AssessmentStatus


class WebAnalyzerBase:
    scope = TargetScope.CLIENT_FACING_ENDPOINT

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


class HttpsEnforcedAnalyzer(WebAnalyzerBase):
    control_id = "DP-B2"
    def analyze(self,target,web):
        evidence=web.http(target.service_url); requested=urlsplit(evidence["requested_url"]).scheme.lower(); final=urlsplit(evidence["final_url"]).scheme.lower(); compliant=requested=="https" and final=="https"
        return self.result(target,AssessmentStatus.COMPLIANT if compliant else AssessmentStatus.NON_COMPLIANT,f"requested_scheme={requested}; final_scheme={final}; redirects={evidence['redirect_count']}",evidence)


class TrustedCertificateAnalyzer(WebAnalyzerBase):
    control_id = "DP-B3"
    def analyze(self,target,web):
        evidence=web.certificate(target.service_url); days=evidence.get("days_remaining"); compliant=evidence.get("trusted_by_client") is True and days is not None and days>0
        return self.result(target,AssessmentStatus.COMPLIANT if compliant else AssessmentStatus.NON_COMPLIANT,f"trusted_by_client={str(evidence.get('trusted_by_client')).lower()}; days_remaining={days}",evidence)


class NosniffHeaderAnalyzer(WebAnalyzerBase):
    control_id = "AS-B13"
    def analyze(self,target,web):
        evidence=web.http(target.service_url); headers={k.lower():v for k,v in evidence["headers"].items()}; value=headers.get("x-content-type-options",""); compliant=value.strip().lower()=="nosniff"
        return self.result(target,AssessmentStatus.COMPLIANT if compliant else AssessmentStatus.NON_COMPLIANT,f"X-Content-Type-Options={value or '<missing>'}",{"requested_url":evidence["requested_url"],"final_url":evidence["final_url"],"X-Content-Type-Options":value or "<missing>"})


class HstsHeaderAnalyzer(WebAnalyzerBase):
    control_id = "DP-B6"
    def analyze(self,target,web):
        evidence=web.http(target.service_url); headers={k.lower():v for k,v in evidence["headers"].items()}; value=headers.get("strict-transport-security",""); compliant="max-age=" in value.lower()
        return self.result(target,AssessmentStatus.COMPLIANT if compliant else AssessmentStatus.NON_COMPLIANT,f"Strict-Transport-Security={value or '<missing>'}",{"requested_url":evidence["requested_url"],"final_url":evidence["final_url"],"Strict-Transport-Security":value or "<missing>"})


class TechnologyBannerAnalyzer(WebAnalyzerBase):
    control_id = "SI-A9"
    sensitive=("server","x-powered-by","x-aspnet-version","x-aspnetmvc-version")
    def analyze(self,target,web):
        evidence=web.http(target.service_url); headers={k.lower():v for k,v in evidence["headers"].items()}; found={name:headers[name] for name in self.sensitive if headers.get(name)}; status=AssessmentStatus.WARNING if found else AssessmentStatus.COMPLIANT
        return self.result(target,status,"exposed_headers="+(str(found) if found else "none"),{"requested_url":evidence["requested_url"],"final_url":evidence["final_url"],"exposed_headers":found})


def build_batch3_analyzers(control_registry):
    return [HttpsEnforcedAnalyzer(control_registry),TrustedCertificateAnalyzer(control_registry),NosniffHeaderAnalyzer(control_registry),HstsHeaderAnalyzer(control_registry),TechnologyBannerAnalyzer(control_registry)]
