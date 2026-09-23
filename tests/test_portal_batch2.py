from analysis.analyzers.portal.batch2 import *
from analysis.models import AssessmentStatus
from controls.registry import ControlRegistry
from core.models import TargetContext
class Cache:
    def __init__(self,self_payload=None,props=None): self.self_payload=self_payload or {}; self.props=props or {}
    def get_absolute(self,target,endpoint): return {"endpoint":endpoint,"payload":self.props if "portaladmin" in endpoint else self.self_payload}
def target(): return TargetContext("p","Portal","portal","enterprise",metadata={"urls":{"sharing_rest":"https://x/portal/sharing/rest","portal_admin":"https://x/portal/portaladmin"}})
def test_servlets_secure_defaults():
    c=Cache(props={}); r=ControlRegistry(); assert LegendServletAnalyzer(r).analyze(target(),c).status==AssessmentStatus.COMPLIANT; assert PrintServletAnalyzer(r).analyze(target(),c).status==AssessmentStatus.COMPLIANT; assert WfsServletAnalyzer(r).analyze(target(),c).status==AssessmentStatus.COMPLIANT
def test_public_sharing_non_compliant(): assert CanSharePublicAnalyzer(ControlRegistry()).analyze(target(),Cache(self_payload={"canSharePublic":True})).status==AssessmentStatus.NON_COMPLIANT
def test_arcgis_login_with_idp_non_compliant(): assert ArcGISLoginsAnalyzer(ControlRegistry()).analyze(target(),Cache(self_payload={"canSigninArcGIS":True,"canSigninIDP":True})).status==AssessmentStatus.NON_COMPLIANT
def test_comments_enabled_warning(): assert ItemCommentsAnalyzer(ControlRegistry()).analyze(target(),Cache(self_payload={"commentsEnabled":True})).status==AssessmentStatus.WARNING
def test_banner_requires_both_enabled(): assert AccessNoticeBannerAnalyzer(ControlRegistry()).analyze(target(),Cache(self_payload={"anonymousAccessNotice":{"enabled":True},"informationalBanner":{"enabled":False}})).status==AssessmentStatus.NON_COMPLIANT
