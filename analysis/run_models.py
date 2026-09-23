from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass
class AssessmentRun:
    run_id: str = field(default_factory=lambda: str(uuid4()))
    catalog_version: str = "unknown"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None
    connected_targets: int = 0
    executed_controls: int = 0
    result_count: int = 0
    error_count: int = 0

    def complete(self, results, executed_controls):
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self.executed_controls = executed_controls
        self.result_count = len(results)
        self.error_count = sum(1 for result in results if result.status.value == "ERROR")
