from dataclasses import dataclass,field
from enum import Enum
from typing import Any,Optional
class AssessmentStatus(str,Enum):
    COMPLIANT="SESUAI"; NON_COMPLIANT="TIDAK SESUAI"; WARNING="PERINGATAN"; NEEDS_REVIEW="PERLU TINJAUAN"; NOT_APPLICABLE="TIDAK BERLAKU"; NOT_ASSESSABLE="TIDAK DAPAT DINILAI"; ERROR="ERROR"
@dataclass
class AssessmentResult:
    control_id:str; control_name:str; target_id:str; target_name:str; component_type:str; profile:str; area:str; verification_method:str; implementation_side:str; status:AssessmentStatus; security_risk:str; privacy_risk:str; current_condition:str=""; expected_condition:str=""; recommendation:str=""; evidence:dict[str,Any]=field(default_factory=dict); reviewer_decision:Optional[str]=None; reviewer_notes:Optional[str]=None; implementation_supported:bool=False; implementation_readiness:Optional[str]=None; operational_impact:Optional[str]=None; recovery_plan:Optional[str]=None; error:Optional[str]=None
