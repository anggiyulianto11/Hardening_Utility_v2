from analysis.models import AssessmentStatus
from analysis.semi_automatic import EvidenceReference, SemiAutomaticWorkspace
from controls.registry import ControlRegistry


def test_workspace_contains_only_semi_automatic_controls():
    workspace = SemiAutomaticWorkspace(ControlRegistry())
    assert workspace.all()
    assert all(item.verification_method == "Semi Otomatis" for item in workspace.all())


def test_reviewer_decision_and_evidence():
    workspace = SemiAutomaticWorkspace(ControlRegistry())
    review = workspace.all()[0]
    review.set_decision(AssessmentStatus.COMPLIANT.value, "Evidence verified")
    review.add_evidence(EvidenceReference("Ticket", "INC-123", "ticket"))
    assert review.status == "SESUAI"
    assert review.evidence_references[0].location == "INC-123"


def test_sensitive_evidence_location_is_redacted():
    workspace = SemiAutomaticWorkspace(ControlRegistry())
    review = workspace.all()[0]
    review.add_evidence(EvidenceReference("API", "https://host/path?token=secret", "other"))
    data = review.to_safe_dict()
    assert "secret" not in str(data)
