from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import json

from analysis.evidence_sanitizer import sanitize_evidence
from analysis.models import AssessmentStatus


@dataclass
class EvidenceReference:
    label: str
    location: str
    evidence_type: str = "document"
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = ""


@dataclass
class SemiAutomaticReview:
    control_id: str
    control_name: str
    profile: str
    area: str
    verification_method: str
    security_risk: str
    privacy_risk: str
    expected_condition: str
    recommendation: str
    status: str = AssessmentStatus.NEEDS_REVIEW.value
    reviewer_notes: str = ""
    evidence_references: list[EvidenceReference] = field(default_factory=list)
    technical_summary: dict = field(default_factory=dict)
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def set_decision(self, status: str, notes: str = ""):
        allowed = {item.value for item in AssessmentStatus}
        if status not in allowed:
            raise ValueError(f"Status tidak valid: {status}")
        self.status = status
        self.reviewer_notes = notes.strip()
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_evidence(self, reference: EvidenceReference):
        self.evidence_references.append(reference)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_safe_dict(self):
        return sanitize_evidence(asdict(self))


class SemiAutomaticWorkspace:
    SCHEMA_VERSION = "1.0"

    def __init__(self, control_registry):
        self.control_registry = control_registry
        self.reviews = {
            control.control_id: SemiAutomaticReview(
                control_id=control.control_id,
                control_name=control.control_name,
                profile=control.profile,
                area=control.area,
                verification_method=control.verification_method,
                security_risk=control.security_risk,
                privacy_risk=control.privacy_risk,
                expected_condition=control.expected_condition,
                recommendation=control.recommendation,
            )
            for control in control_registry.get_all_controls()
            if control.verification_method == "Semi Otomatis"
        }

    def merge_assessment_results(self, results):
        for result in results or []:
            review = self.reviews.get(result.control_id)
            if review is None:
                continue
            review.technical_summary = sanitize_evidence({
                "target": result.target_name,
                "component": result.component_type,
                "current_condition": result.current_condition,
                "automated_status": result.status.value,
                "evidence": result.evidence,
                "error": result.error,
            })
            review.updated_at = datetime.now(timezone.utc).isoformat()

    def all(self):
        return sorted(self.reviews.values(), key=lambda item: self.control_registry.get_control_by_id(item.control_id).sequence)

    def get(self, control_id: str) -> Optional[SemiAutomaticReview]:
        return self.reviews.get(control_id)

    def save(self, path):
        payload = sanitize_evidence({
            "schema_version": self.SCHEMA_VERSION,
            "catalog_version": self.control_registry.metadata.get("catalog_version"),
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "reviews": [item.to_safe_dict() for item in self.all()],
        })
        destination = Path(path)
        destination.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return destination

    def load(self, path):
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema_version") != self.SCHEMA_VERSION:
            raise ValueError("Versi workspace evidence tidak didukung.")
        for raw in payload.get("reviews", []):
            review = self.reviews.get(raw.get("control_id"))
            if review is None:
                continue
            review.status = raw.get("status", review.status)
            review.reviewer_notes = raw.get("reviewer_notes", "")
            review.technical_summary = sanitize_evidence(raw.get("technical_summary") or {})
            review.evidence_references = [EvidenceReference(**item) for item in raw.get("evidence_references", [])]
            review.updated_at = raw.get("updated_at", review.updated_at)
        return self
