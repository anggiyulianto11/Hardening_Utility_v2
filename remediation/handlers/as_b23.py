from datetime import datetime, timezone
from pathlib import Path
import json

from analysis.evidence_sanitizer import sanitize_evidence
from remediation.backup_store import RemediationBackupStore
from remediation.models import RemediationOutcome, RemediationPreview, RemediationState


class ASB23JSONPRemediationHandler:
    control_id = "AS-B23"
    property_name = "callbackFunctionsEnabled"
    target_value = False
    relative_endpoint = "system/handlers/rest/servicesdirectory"

    def __init__(self, client, token_resolver, backup_store=None):
        self.client = client
        self.token_resolver = token_resolver
        self.backup_store = backup_store or RemediationBackupStore()

    def endpoint(self, target):
        return f"{target.effective_admin_url.rstrip('/')}/{self.relative_endpoint}"

    def read_live(self, target):
        endpoint = self.endpoint(target)
        payload = self.client.request_json(
            "GET",
            endpoint,
            params={
                "token": self.token_resolver(target),
                "f": "json",
                "_ts": str(__import__("time").time_ns()),
            },
        )
        if not isinstance(payload, dict):
            raise RuntimeError("Services Directory endpoint tidak mengembalikan JSON object.")
        return payload

    @staticmethod
    def normalize(value):
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
        return None

    def preview(self, target):
        current = self.read_live(target)
        raw = current.get(self.property_name)
        normalized = self.normalize(raw)
        endpoint = self.endpoint(target)
        if normalized is False:
            state = RemediationState.ALREADY_COMPLIANT
            reason = "JSONP callback functions sudah disabled. Apply akan dilewati."
        elif normalized is True:
            state = RemediationState.READY
            reason = "Nilai live dapat dikenali dan target perubahan deterministik."
        else:
            state = RemediationState.BLOCKED
            reason = (
                "Property callbackFunctionsEnabled tidak tersedia atau nilainya ambigu. "
                "Apply diblokir agar utility tidak menebak konfigurasi."
            )
        return RemediationPreview(
            control_id=self.control_id,
            target_id=target.target_id,
            target_name=target.target_name,
            component_type=target.component_type,
            current_value=raw if self.property_name in current else "<not published>",
            target_value=False,
            state=state,
            impact=(
                "Aplikasi legacy yang masih menggunakan JSONP callback dapat berhenti bekerja. "
                "ArcGIS REST JSON biasa tidak dinonaktifkan."
            ),
            endpoint=endpoint,
            reason=reason,
            changed_property=self.property_name,
        )

    @staticmethod
    def build_edit_payload(current, token, target_value):
        payload = {
            key: value for key, value in current.items()
            if isinstance(value, (str, int, float, bool))
            and key not in ("status", "success", "error")
        }
        payload["callbackFunctionsEnabled"] = "true" if target_value else "false"
        payload["token"] = token
        payload["f"] = "json"
        return payload

    def apply(self, target):
        current = self.read_live(target)
        normalized = self.normalize(current.get(self.property_name))
        if normalized is False:
            return RemediationOutcome(
                True, self.control_id, target.target_id, target.target_name,
                RemediationState.ALREADY_COMPLIANT, verified_value=False,
                message="Target sudah compliant; tidak ada POST yang dikirim.",
            )
        if normalized is not True:
            return RemediationOutcome(
                False, self.control_id, target.target_id, target.target_name,
                RemediationState.BLOCKED,
                message="Nilai live ambigu; Apply diblokir tanpa membuat perubahan.",
            )
        endpoint = self.endpoint(target)
        backup_file, metadata_file = self.backup_store.create(
            self.control_id, target, endpoint, current,
            self.property_name, False,
        )
        token = self.token_resolver(target)
        payload = self.build_edit_payload(current, token, False)
        response = self.client.request_json(
            "POST", f"{endpoint}/edit", data=payload,
        )
        verified = self.read_live(target)
        verified_value = self.normalize(verified.get(self.property_name))
        ok = verified_value is False
        self.backup_store.update_metadata(
            metadata_file,
            apply_response=sanitize_evidence(response),
            verified_value=verified.get(self.property_name),
            status="verified_success" if ok else "verification_failed",
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        if not ok:
            return RemediationOutcome(
                False, self.control_id, target.target_id, target.target_name,
                RemediationState.ERROR, verified_value=verified.get(self.property_name),
                backup_file=str(backup_file), metadata_file=str(metadata_file),
                message="POST selesai tetapi live verification gagal.",
            )
        return RemediationOutcome(
            True, self.control_id, target.target_id, target.target_name,
            RemediationState.VERIFIED, verified_value=False,
            backup_file=str(backup_file), metadata_file=str(metadata_file),
            message="JSONP disabled dan telah diverifikasi dari endpoint live.",
        )

    def rollback(self, target, backup_file):
        path = Path(backup_file)
        if not path.exists():
            raise RuntimeError(f"Backup tidak ditemukan: {path}")
        previous = json.loads(path.read_text(encoding="utf-8"))
        expected = self.normalize(previous.get(self.property_name))
        if expected is None:
            raise RuntimeError("Backup tidak memiliki nilai callbackFunctionsEnabled yang valid.")
        current = self.read_live(target)
        current_value = self.normalize(current.get(self.property_name))
        if current_value is expected:
            return RemediationOutcome(
                True, self.control_id, target.target_id, target.target_name,
                RemediationState.ROLLED_BACK, verified_value=expected,
                backup_file=str(path), message="Live state sudah sama dengan backup.",
            )
        token = self.token_resolver(target)
        payload = self.build_edit_payload(current, token, expected)
        endpoint = self.endpoint(target)
        response = self.client.request_json("POST", f"{endpoint}/edit", data=payload)
        verified = self.read_live(target)
        actual = self.normalize(verified.get(self.property_name))
        ok = actual is expected
        metadata_file = path.parent / "metadata.json"
        if metadata_file.exists():
            self.backup_store.update_metadata(
                metadata_file,
                rollback_response=sanitize_evidence(response),
                rollback_verified_value=verified.get(self.property_name),
                status="rolled_back" if ok else "rollback_verification_failed",
                rolled_back_at=datetime.now(timezone.utc).isoformat(),
            )
        if not ok:
            raise RuntimeError("Rollback POST selesai tetapi live verification tidak sesuai backup.")
        return RemediationOutcome(
            True, self.control_id, target.target_id, target.target_name,
            RemediationState.ROLLED_BACK, verified_value=actual,
            backup_file=str(path), message="Rollback berhasil dan diverifikasi live.",
        )

