import json
from pathlib import Path
from controls.models import ControlDefinition

_ROOT = Path(__file__).resolve().parent / "definitions"

def load_catalog() -> tuple[dict, list[ControlDefinition]]:
    metadata=json.loads((_ROOT/"catalog_metadata.json").read_text(encoding="utf-8"))
    records=[]
    for name in ("basic_controls.json","advanced_controls.json"):
        records.extend(json.loads((_ROOT/name).read_text(encoding="utf-8")))
    return metadata,[ControlDefinition(**item) for item in records]
