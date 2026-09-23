from analysis.analyzers.web.batch3 import *
from analysis.models import AssessmentStatus
from controls.registry import ControlRegistry
from core.models import TargetContext
class Web:
    def __init__(self,headers=None,final="https://x/portal",cert=None): self.headers=headers or {}; self.final=final; self.cert=cert or {"trusted_by_client":True,"days_remaining":30}
    def http(self,url): return {"requested_url":url,"final_url":self.final,"status_code":200,"redirect_count":0,"headers":self.headers}
    def certificate(self,url): return self.cert
def target(): return TargetContext("p","Portal","portal","enterprise",service_url="https://x/portal")
def test_https_compliant(): assert HttpsEnforcedAnalyzer(ControlRegistry()).analyze(target(),Web()).status==AssessmentStatus.COMPLIANT
def test_nosniff_missing_noncompliant(): assert NosniffHeaderAnalyzer(ControlRegistry()).analyze(target(),Web()).status==AssessmentStatus.NON_COMPLIANT
def test_hsts_present_compliant(): assert HstsHeaderAnalyzer(ControlRegistry()).analyze(target(),Web({"Strict-Transport-Security":"max-age=31536000"})).status==AssessmentStatus.COMPLIANT
def test_certificate_valid_compliant(): assert TrustedCertificateAnalyzer(ControlRegistry()).analyze(target(),Web()).status==AssessmentStatus.COMPLIANT
def test_banner_warning(): assert TechnologyBannerAnalyzer(ControlRegistry()).analyze(target(),Web({"Server":"nginx/1.2"})).status==AssessmentStatus.WARNING
