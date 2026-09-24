from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from analysis.evidence_sanitizer import sanitize_evidence


class RemediationBackupStore:
    def __init__(self, root=None):
        self.root = Path(root or (Path.cwd() / "backups" / "remediation"))

    @staticmethod
    def _safe_name(value):
        text = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(value))
        return text.strip("_")[:80] or "target"

    def create(self, control_id, target, endpoint, current_payload, property_name, target_value):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        folder = self.root / f"{stamp}_{self._safe_name(target.target_name)}_{control_id}"
        folder.mkdir(parents=True, exist_ok=False)
        safe_payload = sanitize_evidence(current_payload)
        backup_file = folder / "before.json"
        backup_bytes = json.dumps(safe_payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        backup_file.write_bytes(backup_bytes)
        metadata = sanitize_evidence({
            "schema_version": "1.0",
            "control_id": control_id,
            "target_id": target.target_id,
            "target_name": target.target_name,
            "component_type": target.component_type,
            "effective_admin_url": target.effective_admin_url,
            "endpoint": endpoint,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "changed_property": property_name,
            "property_was_present": property_name in current_payload,
            "previous_value": current_payload.get(property_name),
            "target_value": target_value,
            "backup_sha256": hashlib.sha256(backup_bytes).hexdigest(),
            "status": "backup_created",
            "sensitive_values_saved": False,
        })
        metadata_file = folder / "metadata.json"
        metadata_file.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        return backup_file, metadata_file

    @staticmethod
    def update_metadata(metadata_file, **updates):
        path = Path(metadata_file)
        data = json.loads(path.read_text(encoding="utf-8"))
        data.update(sanitize_evidence(updates))
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
