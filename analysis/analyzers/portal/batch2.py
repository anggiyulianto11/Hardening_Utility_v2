from analysis.applicability import TargetScope
from analysis.models import AssessmentResult, AssessmentStatus


class PortalAnalyzerBase:
    scope = TargetScope.PORTAL
    source = "portal_self"

    def __init__(self, control_registry):
        self.definition = control_registry.get_control_by_id(self.control_id)
        if self.definition is None:
            raise ValueError(f"Control {self.control_id} tidak tersedia di katalog.")

    def _record(self, target, cache):
        urls = target.metadata["urls"]
        endpoint = (
            f"{urls['sharing_rest']}/portals/self"
            if self.source == "portal_self"
            else f"{urls['portal_admin']}/system/properties"
        )
        return cache.get_absolute(target, endpoint)

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


class FalsePortalSystemPropertyAnalyzer(PortalAnalyzerBase):
    source = "portal_system_properties"
    default_value = False

    def analyze(self, target, cache):
        record = self._record(target, cache)
        payload = record["payload"]
        explicit = self.property_name in payload
        value = payload.get(self.property_name, self.default_value)
        compliant = not _as_bool(value)
        shown = value if explicit else f"<default {str(self.default_value).lower()}>"
        return self.result(
            target,
            AssessmentStatus.COMPLIANT if compliant else AssessmentStatus.NON_COMPLIANT,
            f"{self.property_name}={shown}",
            {"endpoint": record["endpoint"], self.property_name: shown},
        )


class LegendServletAnalyzer(FalsePortalSystemPropertyAnalyzer):
    control_id = "AS-B8"
    property_name = "enableLegendsService"


class PrintServletAnalyzer(FalsePortalSystemPropertyAnalyzer):
    control_id = "AS-B9"
    property_name = "enablePrintService"


class WfsServletAnalyzer(FalsePortalSystemPropertyAnalyzer):
    control_id = "AS-B10"
    property_name = "enableWfsService"


class DisableSignupAnalyzer(PortalAnalyzerBase):
    control_id = "AS-B12"
    source = "portal_system_properties"

    def analyze(self, target, cache):
        record = self._record(target, cache)
        payload = record["payload"]
        explicit = "disableSignup" in payload
        value = payload.get("disableSignup", True)
        shown = value if explicit else "<secure default true>"
        return self.result(
            target,
            AssessmentStatus.COMPLIANT if _as_bool(value) else AssessmentStatus.NON_COMPLIANT,
            f"disableSignup={shown}",
            {"endpoint": record["endpoint"], "disableSignup": shown},
        )


class DisableServicesDirectoryAnalyzer(PortalAnalyzerBase):
    control_id = "AS-B16"
    source = "portal_system_properties"

    def analyze(self, target, cache):
        record = self._record(target, cache)
        value = record["payload"].get("disableServicesDirectory", False)
        return self.result(
            target,
            AssessmentStatus.COMPLIANT if _as_bool(value) else AssessmentStatus.NON_COMPLIANT,
            f"disableServicesDirectory={str(value).lower()}",
            {"endpoint": record["endpoint"], "disableServicesDirectory": value},
        )


class CanSharePublicAnalyzer(PortalAnalyzerBase):
    control_id = "IA-B9"
    def analyze(self, target, cache):
        record=self._record(target,cache); value=record["payload"].get("canSharePublic",True)
        return self.result(target,AssessmentStatus.NON_COMPLIANT if _as_bool(value) else AssessmentStatus.COMPLIANT,f"canSharePublic={str(value).lower()}",{"endpoint":record["endpoint"],"canSharePublic":value})


class PublicProfileAnalyzer(PortalAnalyzerBase):
    control_id = "IA-B10"
    def analyze(self,target,cache):
        record=self._record(target,cache); value=record["payload"].get("updateUserProfileDisabled",False)
        return self.result(target,AssessmentStatus.COMPLIANT if _as_bool(value) else AssessmentStatus.NON_COMPLIANT,f"updateUserProfileDisabled={str(value).lower()}",{"endpoint":record["endpoint"],"updateUserProfileDisabled":value})


class AccessNoticeBannerAnalyzer(PortalAnalyzerBase):
    control_id = "AS-B21"
    def analyze(self,target,cache):
        record=self._record(target,cache); payload=record["payload"]
        notice=payload.get("anonymousAccessNotice") or {}; banner=payload.get("informationalBanner") or {}
        notice_enabled=_as_bool(notice.get("enabled",False)) if isinstance(notice,dict) else False
        banner_enabled=_as_bool(banner.get("enabled",False)) if isinstance(banner,dict) else False
        status=AssessmentStatus.COMPLIANT if notice_enabled and banner_enabled else AssessmentStatus.NON_COMPLIANT
        return self.result(target,status,f"anonymousAccessNotice.enabled={str(notice_enabled).lower()}; informationalBanner.enabled={str(banner_enabled).lower()}",{"endpoint":record["endpoint"],"anonymousAccessNotice":{"enabled":notice_enabled},"informationalBanner":{"enabled":banner_enabled}})


class SocialMediaLinksAnalyzer(PortalAnalyzerBase):
    control_id = "IA-B24"
    def analyze(self,target,cache):
        record=self._record(target,cache); value=record["payload"].get("showSocialMediaLinks",True)
        return self.result(target,AssessmentStatus.NON_COMPLIANT if _as_bool(value) else AssessmentStatus.COMPLIANT,f"showSocialMediaLinks={str(value).lower()}",{"endpoint":record["endpoint"],"showSocialMediaLinks":value})


class ArcGISLoginsAnalyzer(PortalAnalyzerBase):
    control_id = "IA-A7"
    def analyze(self,target,cache):
        record=self._record(target,cache); payload=record["payload"]
        arcgis=_as_bool(payload.get("canSigninArcGIS",True)); idp=_as_bool(payload.get("canSigninIDP",False))
        if not idp: status=AssessmentStatus.NEEDS_REVIEW
        else: status=AssessmentStatus.COMPLIANT if not arcgis else AssessmentStatus.NON_COMPLIANT
        return self.result(target,status,f"canSigninArcGIS={str(arcgis).lower()}; canSigninIDP={str(idp).lower()}",{"endpoint":record["endpoint"],"canSigninArcGIS":arcgis,"canSigninIDP":idp})


class ItemCommentsAnalyzer(PortalAnalyzerBase):
    control_id = "IA-A10"
    def analyze(self,target,cache):
        record=self._record(target,cache); payload=record["payload"]
        if "commentsEnabled" not in payload:
            return self.result(target,AssessmentStatus.NOT_ASSESSABLE,"commentsEnabled=<not published>",{"endpoint":record["endpoint"],"commentsEnabled":"<not published>"})
        value=_as_bool(payload.get("commentsEnabled")); status=AssessmentStatus.WARNING if value else AssessmentStatus.COMPLIANT
        return self.result(target,status,f"commentsEnabled={str(value).lower()}",{"endpoint":record["endpoint"],"commentsEnabled":value})


def _as_bool(value):
    if isinstance(value,bool): return value
    return str(value).strip().lower() in ("true","1","yes","on")


def build_batch2_analyzers(control_registry):
    return [LegendServletAnalyzer(control_registry),PrintServletAnalyzer(control_registry),WfsServletAnalyzer(control_registry),DisableSignupAnalyzer(control_registry),DisableServicesDirectoryAnalyzer(control_registry),CanSharePublicAnalyzer(control_registry),PublicProfileAnalyzer(control_registry),AccessNoticeBannerAnalyzer(control_registry),SocialMediaLinksAnalyzer(control_registry),ArcGISLoginsAnalyzer(control_registry),ItemCommentsAnalyzer(control_registry)]
