from enum import Enum


class TargetScope(str, Enum):
    PORTAL = "PORTAL"
    ANY_SERVER = "ANY_SERVER"
    HOSTING_SERVER = "HOSTING_SERVER"
    FEDERATED_SERVER = "FEDERATED_SERVER"
    STANDALONE_SERVER = "STANDALONE_SERVER"
    CLIENT_FACING_ENDPOINT = "CLIENT_FACING_ENDPOINT"


def applies_to(scope, target):
    if target.connection_state.value != "CONNECTED":
        return False
    if scope == TargetScope.PORTAL:
        return target.component_type == "portal"
    if scope == TargetScope.ANY_SERVER:
        return target.component_type == "server"
    if scope == TargetScope.CLIENT_FACING_ENDPOINT:
        return bool(target.service_url) and target.component_type in ("portal", "server")
    if scope == TargetScope.HOSTING_SERVER:
        return target.component_type == "server" and "HOSTING_SERVER" in target.roles
    if scope == TargetScope.FEDERATED_SERVER:
        return target.component_type == "server" and target.deployment_mode == "enterprise"
    if scope == TargetScope.STANDALONE_SERVER:
        return target.component_type == "server" and target.deployment_mode == "standalone_server"
    return False
