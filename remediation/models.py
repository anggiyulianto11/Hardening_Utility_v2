from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class RemediationState(str, Enum):
    READY = "READY"
    ALREADY_COMPLIANT = "ALREADY COMPLIANT"
    BLOCKED = "BLOCKED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    ROLLED_BACK = "ROLLED BACK"
    ERROR = "ERROR"


@dataclass
class RemediationPreview:
    control_id: str
    target_id: str
    target_name: str
    component_type: str
    current_value: object
    target_value: object
    state: RemediationState
    impact: str
    endpoint: str
    reason: str = ""
    changed_property: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class RemediationOutcome:
    success: bool
    control_id: str
    target_id: str
    target_name: str
    state: RemediationState
    verified_value: object = None
    backup_file: str = ""
    metadata_file: str = ""
    message: str = ""
