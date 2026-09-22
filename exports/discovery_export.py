import json
from datetime import datetime, timezone
from pathlib import Path
from core.security import sanitize_data
def build_discovery_payload(result):
    return sanitize_data({"schema_version":"1.0","exported_at":datetime.now(timezone.utc).isoformat(),"target_type":result.target_type.value,"targets":[x.to_safe_dict() for x in result.targets]})
def export_discovery(result,path):
    destination=Path(path); destination.write_text(json.dumps(build_discovery_payload(result),ensure_ascii=False,indent=2),encoding="utf-8"); return destination
