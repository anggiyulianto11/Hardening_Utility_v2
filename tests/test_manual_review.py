from manual_review.models import ManualEvidenceReference, NOT_REVIEWED
from manual_review.workspace import ManualReviewWorkspace
from controls.registry import ControlRegistry


def test_workspace_loads_only_manual_controls():
    workspace = ManualReviewWorkspace(ControlRegistry())
    assert workspace.all()
    assert all(
        workspace.control_registry.get_control_by_id(item.control_id).verification_method
        == "Peninjauan Manual"
        for item in workspace.all()
    )


def test_initial_status_is_not_reviewed():
    workspace = ManualReviewWorkspace(ControlRegistry())
    assert all(item.status == NOT_REVIEWED for item in workspace.all())
    assert workspace.completion()["percent"] == 0.0


def test_decision_updates_completion():
    workspace = ManualReviewWorkspace(ControlRegistry())
    record = workspace.all()[0]
    record.set_decision("SESUAI", reviewer_name="Assessor")
    workspace.mark_dirty()
    assert workspace.completion()["decided"] == 1
    assert workspace.dirty is True


def test_evidence_secret_is_redacted():
    workspace = ManualReviewWorkspace(ControlRegistry())
    record = workspace.all()[0]
    record.add_evidence(
        ManualEvidenceReference(
            label="API evidence",
            location="https://host/path?token=secret-value",
        )
    )
    assert "secret-value" not in str(record.to_safe_dict())
