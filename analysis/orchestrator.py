from analysis.analyzer_registry import AnalyzerRegistry
from analysis.applicability import applies_to, TargetScope
from analysis.evidence_cache import EvidenceCache
from analysis.identity_evidence import PortalMemberCollector
from analysis.web_evidence_cache import WebEvidenceCache
from analysis.models import AssessmentResult, AssessmentStatus
from analysis.run_models import AssessmentRun
from analysis.analyzers.server.batch1 import build_batch1_analyzers
from analysis.analyzers.portal.batch2 import build_batch2_analyzers
from analysis.analyzers.web.batch3 import build_batch3_analyzers
from analysis.analyzers.governance.batch4a import build_batch4a_analyzers
from analysis.analyzers.identity.batch4b import build_batch4b_analyzers
from core.security import redact_text


class AssessmentOrchestrator:
    def __init__(self, connection_registry, control_registry):
        self.connection_registry=connection_registry; self.control_registry=control_registry; self.registry=AnalyzerRegistry()
        analyzers=build_batch1_analyzers(control_registry)+build_batch2_analyzers(control_registry)+build_batch3_analyzers(control_registry)+build_batch4a_analyzers(control_registry)+build_batch4b_analyzers(control_registry)
        for analyzer in analyzers: self.registry.register(analyzer)
    def _token(self,target):
        record=self.connection_registry.tokens.portal_token if target.component_type=="portal" else self.connection_registry.tokens.server_tokens.get(target.service_url)
        if record and record.valid(): return record.token
        raise RuntimeError("Token tidak tersedia atau kedaluwarsa. Jalankan discovery kembali.")
    def analyze(self):
        targets=self.connection_registry.get_connected_targets(); run=AssessmentRun(catalog_version=self.control_registry.metadata.get("catalog_version","unknown"),connected_targets=len(targets)); api_cache=EvidenceCache(self.connection_registry.client,self._token); web_cache=WebEvidenceCache(self.connection_registry.client.session,self.connection_registry.client.verify_tls,self.connection_registry.client.timeout); member_cache=PortalMemberCollector(self.connection_registry.client,self._token); results=[]
        identity_ids={"IA-B1","IA-A3","IA-B13","IA-A1"}
        for analyzer in self.registry.all():
            for target in targets:
                if not applies_to(analyzer.scope,target): continue
                try:
                    if analyzer.control_id in identity_ids:
                        evidence=dict(member_cache.collect(target)); urls=target.metadata["urls"]; evidence["portal_self"]=api_cache.get_absolute(target,f"{urls['sharing_rest']}/portals/self")["payload"]; results.append(analyzer.analyze(target,evidence))
                    else:
                        cache=web_cache if analyzer.scope==TargetScope.CLIENT_FACING_ENDPOINT else api_cache; results.append(analyzer.analyze(target,cache))
                except Exception as exc:
                    d=analyzer.definition; results.append(AssessmentResult(control_id=d.control_id,control_name=d.control_name,target_id=target.target_id,target_name=target.target_name,component_type=target.component_type,profile=d.profile,area=d.area,verification_method=d.verification_method,implementation_side=d.implementation_side,status=AssessmentStatus.ERROR,security_risk=d.security_risk,privacy_risk=d.privacy_risk,expected_condition=d.expected_condition,recommendation=d.recommendation,error=redact_text(exc)))
        run.complete(results,len(self.registry.all())); return run,results,api_cache.request_count+web_cache.request_count+member_cache.request_count
