from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class ControlDefinition:
    sequence: int
    control_id: str
    guide_section: str
    profile: str
    area: str
    control_name: str
    verification_method: str
    implementation_side: str
    security_risk: str
    privacy_risk: str
    responsible_roles: list[str] = field(default_factory=list)
    default_condition: Optional[str] = None
    changeable: bool = False
    portal_scan_reference: Optional[str] = None
    server_scan_reference: Optional[str] = None
    security_adviser_supported: bool = False
    prerequisites: list[str] = field(default_factory=list)
    business_impact: str = ""
    expected_condition: str = ""
    recommendation: str = ""
    verification_guidance: str = ""
    guide_location: str = ""
    official_documentation: Optional[str] = None
    implementation_readiness: Optional[str] = None
    implementation_target: Optional[str] = None
    implementation_parameter_decision: Optional[str] = None
    planned_change: Optional[str] = None
    operational_impact: Optional[str] = None
    recovery_plan: Optional[str] = None
