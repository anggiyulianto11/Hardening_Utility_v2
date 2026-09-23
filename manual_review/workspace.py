import json
from datetime import datetime, timezone
from pathlib import Path

from analysis.evidence_sanitizer import sanitize_evidence
from manual_review.models import (
    ManualEvidenceReference,
    ManualReviewRecord,
    NOT_REVIEWED,
)


class ManualReviewWorkspace:
    SCHEMA_VERSION = "1.0"

    def __init__(self, control_registry):
        self.control_registry = control_registry
        self.source_path = None
        self.last_saved_at = None
        self.dirty = False
        self.records = {}
        for control in control_registry.get_all_controls():
            if control.verification_method != "Peninjauan Manual":
                continue
            self.records[control.control_id] = ManualReviewRecord(
                control_id=control.control_id,
                control_name=control.control_name,
                profile=control.profile,
                area=control.area,
                security_risk=control.security_risk,
                privacy_risk=control.privacy_risk,
                responsible_roles=list(control.responsible_roles),
                expected_condition=control.expected_condition,
                recommendation=control.recommendation,
                verification_guidance=control.verification_guidance,
                prerequisites=list(control.prerequisites),
                business_impact=control.business_impact,
                official_documentation=control.official_documentation,
            )

    def all(self):
        return sorted(
            self.records.values(),
            key=lambda item: self.control_registry.get_control_by_id(
                item.control_id
            ).sequence,
        )

    def get(self, control_id):
        return self.records.get(control_id)

    def mark_dirty(self):
        self.dirty = True

    def completion(self):
        records = self.all()
        decided = [item for item in records if item.status != NOT_REVIEWED]
        return {
            "total": len(records),
            "decided": len(decided),
            "not_reviewed": len(records) - len(decided),
            "percent": round((len(decided) / len(records) * 100), 1)
            if records
            else 100.0,
        }

    def save(self, path):
        saved_at = datetime.now(timezone.utc).isoformat()
        payload = sanitize_evidence(
            {
                "schema_version": self.SCHEMA_VERSION,
                "catalog_version": self.control_registry.metadata.get(
                    "catalog_version"
                ),
                "saved_at": saved_at,
                "records": [item.to_safe_dict() for item in self.all()],
            }
        )
        destination = Path(path)
        destination.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self.source_path = str(destination)
        self.last_saved_at = saved_at
        self.dirty = False
        return destination

    def load(self, path):
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema_version") != self.SCHEMA_VERSION:
            raise ValueError("Versi manual review workspace tidak didukung.")
        for raw in payload.get("records", []):
            record = self.records.get(raw.get("control_id"))
            if record is None:
                continue
            for name in (
                "status",
                "reviewer_name",
                "reviewer_notes",
                "applicability_reason",
                "business_exception",
                "compensating_control",
                "responsible_team",
                "target_remediation_date",
                "updated_at",
            ):
                if name in raw:
                    setattr(record, name, raw.get(name) or "")
            record.evidence_references = [
                ManualEvidenceReference(**item)
                for item in raw.get("evidence_references", [])
            ]
        self.source_path = str(path)
        self.last_saved_at = payload.get("saved_at")
        self.dirty = False
        return self
