from analysis.analyzers.server.as_b23_callback_functions import CallbackFunctionsAnalyzer
from analysis.models import AssessmentStatus
from controls.registry import ControlRegistry
from core.models import TargetContext

class FakeClient:
    def __init__(self,payload): self.payload=payload
    def request_json(self,*args,**kwargs): return self.payload

def target(): return TargetContext("s1","Hosting Server","server","enterprise",effective_admin_url="https://host/server/admin")

def test_default_is_non_compliant():
    result=CallbackFunctionsAnalyzer(FakeClient({}),ControlRegistry()).analyze(target(),"token")
    assert result.status==AssessmentStatus.NON_COMPLIANT
    assert "default enabled" in result.current_condition

def test_false_is_compliant():
    result=CallbackFunctionsAnalyzer(FakeClient({"callbackFunctionsEnabled":False}),ControlRegistry()).analyze(target(),"token")
    assert result.status==AssessmentStatus.COMPLIANT
    assert result.evidence["callbackFunctionsEnabled"] is False
