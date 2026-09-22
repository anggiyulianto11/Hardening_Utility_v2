from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

class TargetType(str, Enum):
    ENTERPRISE = "enterprise"
    STANDALONE_SERVER = "standalone_server"

class ConnectionState(str, Enum):
    CONNECTED = "CONNECTED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NOT_TESTED = "NOT_TESTED"

class ConnectionRoute(str, Enum):
    SERVICE_URL = "SERVICE_URL"
    REGISTERED_ADMIN_URL = "REGISTERED_ADMIN_URL"
    DIRECT_ADMIN_URL = "DIRECT_ADMIN_URL"

class ErrorCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    TLS = "TLS"
    CONNECTION = "CONNECTION"
    TIMEOUT = "TIMEOUT"
    TOKEN_EXCHANGE = "TOKEN_EXCHANGE"
    SERVER_ADMIN = "SERVER_ADMIN"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    UNKNOWN = "UNKNOWN"

@dataclass
class TargetContext:
    target_id: str
    target_name: str
    component_type: str
    deployment_mode: str
    service_url: Optional[str] = None
    registered_admin_url: Optional[str] = None
    effective_admin_url: Optional[str] = None
    version: Optional[str] = None
    roles: list[str] = field(default_factory=list)
    server_functions: list[str] = field(default_factory=list)
    federation_state: str = "standalone"
    connection_state: ConnectionState = ConnectionState.NOT_TESTED
    connection_route: Optional[ConnectionRoute] = None
    error: Optional[str] = None
    error_category: Optional[ErrorCategory] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_safe_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["connection_state"] = self.connection_state.value
        data["connection_route"] = self.connection_route.value if self.connection_route else None
        data["error_category"] = self.error_category.value if self.error_category else None
        return data

@dataclass
class DiscoveryResult:
    target_type: TargetType
    targets: list[TargetContext] = field(default_factory=list)

    @property
    def portal(self) -> Optional[TargetContext]:
        return next((x for x in self.targets if x.component_type == "portal"), None)

    @property
    def servers(self) -> list[TargetContext]:
        return [x for x in self.targets if x.component_type == "server"]

    @property
    def connected_count(self) -> int:
        return sum(x.connection_state == ConnectionState.CONNECTED for x in self.targets)
