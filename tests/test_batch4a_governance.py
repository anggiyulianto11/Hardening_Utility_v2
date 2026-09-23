from analysis.analyzers.governance.batch4a import *
from analysis.models import AssessmentStatus
from controls.registry import ControlRegistry
from core.models import TargetContext

class Cache:
    def __init__(self, payload): self.payload=payload
    def get_json(self,target,path): return {"endpoint":"https://x/admin/"+path,"payload":self.payload}
    def get_absolute(self,target,endpoint): return {"endpoint":endpoint,"payload":self.payload}
def server(): return TargetContext("s","Server","server","enterprise",effective_admin_url="https://x/server/admin")
def portal(): return TargetContext("p","Portal","portal","enterprise",service_url="https://x/portal",metadata={"urls":{"sharing_rest":"https://x/portal/sharing/rest","portal_admin":"https://x/portal/portaladmin"}})
def test_psa_enabled_noncompliant(): assert PrimarySiteAdministratorAnalyzer(ControlRegistry()).analyze(server(),Cache({"disabled":False})).status==AssessmentStatus.NON_COMPLIANT
def test_psa_disabled_compliant(): assert PrimarySiteAdministratorAnalyzer(ControlRegistry()).analyze(server(),Cache({"disabled":True})).status==AssessmentStatus.COMPLIANT
def test_webhook_http_noncompliant(): assert OrganizationWebhooksAnalyzer(ControlRegistry()).analyze(portal(),Cache({"webhooks":[{"name":"a","url":"http://receiver/hook","active":True}]})).status==AssessmentStatus.NON_COMPLIANT
def test_no_webhook_needs_review(): assert OrganizationWebhooksAnalyzer(ControlRegistry()).analyze(portal(),Cache({"webhooks":[]})).status==AssessmentStatus.NEEDS_REVIEW
def test_external_utility_needs_review(): assert UtilityServiceDependenciesAnalyzer(ControlRegistry()).analyze(portal(),Cache({"helperServices":{"geocode":{"url":"https://external.example/geocode"}}})).status==AssessmentStatus.NEEDS_REVIEW
