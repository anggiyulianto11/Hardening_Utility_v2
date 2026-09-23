from analysis.analyzer_registry import AnalyzerRegistry
from analysis.analyzers.server.batch1 import StandardizedQueriesAnalyzer, FeatureServiceXssBasicAnalyzer, FeatureServiceXssAdvancedAnalyzer, TokenHttpGetAnalyzer, ServerLoggingLevelAnalyzer
from analysis.models import AssessmentStatus
from controls.registry import ControlRegistry
from core.models import TargetContext

class Cache:
    def __init__(self,payload): self.payload=payload
    def get_json(self,target,path): return {"endpoint":"https://host/admin/"+path,"payload":self.payload}
def target(): return TargetContext("s","Server","server","enterprise",effective_admin_url="https://host/admin")
def test_registry_rejects_duplicate():
    reg=AnalyzerRegistry(); a=StandardizedQueriesAnalyzer(ControlRegistry()); reg.register(a)
    try: reg.register(a); assert False
    except ValueError: pass
def test_standardized_default_compliant(): assert StandardizedQueriesAnalyzer(ControlRegistry()).analyze(target(),Cache({})).status==AssessmentStatus.COMPLIANT
def test_xss_basic_and_advanced():
    basic=FeatureServiceXssBasicAnalyzer(ControlRegistry()).analyze(target(),Cache({"featureServiceXSSFilter":"input"})); advanced=FeatureServiceXssAdvancedAnalyzer(ControlRegistry()).analyze(target(),Cache({"featureServiceXSSFilter":"input"})); assert basic.status==AssessmentStatus.COMPLIANT and advanced.status==AssessmentStatus.NON_COMPLIANT
def test_http_get_default_disabled_compliant(): assert TokenHttpGetAnalyzer(ControlRegistry()).analyze(target(),Cache({"properties":{}})).status==AssessmentStatus.COMPLIANT
def test_log_info_compliant(): assert ServerLoggingLevelAnalyzer(ControlRegistry()).analyze(target(),Cache({"settings":{"logLevel":"INFO"}})).status==AssessmentStatus.COMPLIANT
