from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

from analysis.evidence_sanitizer import sanitize_evidence


NOT_REVIEWED = "BELUM DIPERIKSA"
ALLOWED_DECISIONS = {
    NOT_REVIEWED,
    "PERLU TINJAUAN",
    "SESUAI",
    "TIDAK SESUAI",
    "PERINGATAN",
    "TIDAK BERLAKU",
    "TIDAK DAPAT DINILAI",
}


@dataclass
class ManualEvidenceReference:
    label: str
    location: str
    evidence_type: str = "document"
    notes: str = ""
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ManualReviewRecord:
    control_id: str
    control_name: str
    profile: str
    area: str
    security_risk: str
    privacy_risk: str
    responsible_roles: list[str]
    expected_condition: str
    recommendation: str
    verification_guidance: str
    prerequisites: list[str]
    business_impact: str
    official_documentation: Optional[str] = None
    status: str = NOT_REVIEWED
    reviewer_name: str = ""
    reviewer_notes: str = ""
    applicability_reason: str = ""
    business_exception: str = ""
    compensating_control: str = ""
    responsible_team: str = ""
    target_remediation_date: str = ""
    evidence_references: list[ManualEvidenceReference] = field(default_factory=list)
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def set_decision(self, status: str, **fields):
        if status not in ALLOWED_DECISIONS:
            raise ValueError(f"Status manual review tidak valid: {status}")
        self.status = status
        for name, value in fields.items():
            if hasattr(self, name):
                setattr(self, name, str(value or "").strip())
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_evidence(self, evidence: ManualEvidenceReference):
        self.evidence_references.append(evidence)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_safe_dict(self):
        return sanitize_evidence(asdict(self))
