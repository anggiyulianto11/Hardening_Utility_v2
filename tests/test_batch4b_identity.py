from analysis.analyzers.identity.batch4b import *
from analysis.models import AssessmentStatus
from controls.registry import ControlRegistry
from core.models import TargetContext

def portal(): return TargetContext("p","Portal","portal","enterprise",metadata={"urls":{"sharing_rest":"https://x/portal/sharing/rest"}})
def members(users,portal_self=None): return {"endpoint":"https://x/users","users":users,"portal_self":portal_self or {}}
def user(ref,provider="arcgis",role="org_user",mfa=True,disabled=False,role_id=None): return {"account_ref":ref,"provider":provider,"role":role,"mfa_enabled":mfa,"disabled":disabled,"role_id":role_id,"last_login":1,"user_type":"creator"}
def test_local_admin_without_mfa_noncompliant(): assert AdministratorMfaAnalyzer(ControlRegistry()).analyze(portal(),members([user("a",role="org_admin",mfa=False)])).status==AssessmentStatus.NON_COMPLIANT
def test_external_admin_needs_review(): assert AdministratorMfaAnalyzer(ControlRegistry()).analyze(portal(),members([user("a",provider="enterprise",role="org_admin",mfa=None)])).status==AssessmentStatus.NEEDS_REVIEW
def test_all_local_users_with_mfa_compliant(): assert AllUsersMfaAnalyzer(ControlRegistry()).analyze(portal(),members([user("a"),user("b")])).status==AssessmentStatus.COMPLIANT
def test_default_viewer_compliant(): assert DefaultRoleAnalyzer(ControlRegistry()).analyze(portal(),members([],{"defaultUserRole":"Viewer"})).status==AssessmentStatus.COMPLIANT
def test_custom_roles_need_review(): assert CustomRolesAnalyzer(ControlRegistry()).analyze(portal(),members([user("a",role="custom",role_id="r1")])).status==AssessmentStatus.NEEDS_REVIEW
