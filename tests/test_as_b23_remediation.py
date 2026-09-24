from pathlib import Path

from remediation.backup_store import RemediationBackupStore
from remediation.handlers.as_b23 import ASB23JSONPRemediationHandler
from remediation.models import RemediationState


class Target:
    target_id = "server-1"
    target_name = "Hosting Server"
    component_type = "server"
    effective_admin_url = "https://example/server/admin"
    service_url = "https://example/server"


class Client:
    def __init__(self, value=True):
        self.value = value
        self.posts = []
    def request_json(self, method, url, **kwargs):
        if method == "GET":
            return {"servicesDirEnabled": True, "callbackFunctionsEnabled": self.value, "allowedOrigins": "https://app"}
        self.posts.append(kwargs["data"])
        self.value = kwargs["data"]["callbackFunctionsEnabled"] == "true"
        return {"status": "success"}


def handler(tmp_path, value=True):
    return ASB23JSONPRemediationHandler(
        Client(value), lambda target: "secret-token",
        RemediationBackupStore(tmp_path),
    )


def test_preview_ready_when_jsonp_enabled(tmp_path):
    assert handler(tmp_path, True).preview(Target()).state == RemediationState.READY


def test_apply_preserves_existing_scalar_properties(tmp_path):
    item = handler(tmp_path, True)
    outcome = item.apply(Target())
    assert outcome.success is True
    payload = item.client.posts[0]
    assert payload["servicesDirEnabled"] is True
    assert payload["allowedOrigins"] == "https://app"
    assert payload["callbackFunctionsEnabled"] == "false"


def test_apply_skips_when_already_compliant(tmp_path):
    item = handler(tmp_path, False)
    outcome = item.apply(Target())
    assert outcome.state == RemediationState.ALREADY_COMPLIANT
    assert item.client.posts == []


def test_backup_does_not_contain_token(tmp_path):
    item = handler(tmp_path, True)
    outcome = item.apply(Target())
    content = Path(outcome.backup_file).read_text(encoding="utf-8")
    assert "secret-token" not in content


def test_rollback_only_restores_owned_property(tmp_path):
    item = handler(tmp_path, True)
    applied = item.apply(Target())
    item.client.value = False
    outcome = item.rollback(Target(), applied.backup_file)
    assert outcome.verified_value is True
    assert item.client.posts[-1]["allowedOrigins"] == "https://app"
