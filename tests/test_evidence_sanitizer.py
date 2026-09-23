from analysis.evidence_sanitizer import sanitize_evidence
def test_recursive_secret_redaction():
 x=sanitize_evidence({"token":"abc","nested":{"sharedKey":"secret","safe":"ok"}}); assert x["token"]=="[REDACTED]"; assert x["nested"]["sharedKey"]=="[REDACTED]"; assert x["nested"]["safe"]=="ok"
