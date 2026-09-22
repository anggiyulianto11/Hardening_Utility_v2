from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

class TargetType(str, Enum):
    ENTERPRISE='enterprise'
    STANDALONE_SERVER='standalone_server'

class ConnectionState(str, Enum):
    CONNECTED='CONNECTED'
    FAILED='FAILED'
    PARTIAL='PARTIAL'
    NOT_TESTED='NOT_TESTED'

class ConnectionRoute(str, Enum):
    SERVICE_URL='SERVICE_URL'
    REGISTERED_ADMIN_URL='REGISTERED_ADMIN_URL'

class ErrorCategory(str, Enum):
    AUTHENTICATION='AUTHENTICATION'
    AUTHORIZATION='AUTHORIZATION'
    TLS='TLS'
    CONNECTION='CONNECTION'
    TIMEOUT='TIMEOUT'
    TOKEN_EXCHANGE='TOKEN_EXCHANGE'
    SERVER_ADMIN='SERVER_ADMIN'
    UNKNOWN='UNKNOWN'

@dataclass
class TargetContext:
    target_id:str
    target_name:str
    component_type:str
    deployment_mode:str
    service_url: Optional[str]=None
    registered_admin_url: Optional[str]=None
    effective_admin_url: Optional[str]=None
    version: Optional[str]=None
    roles:list[str]=field(default_factory=list)
    server_functions:list[str]=field(default_factory=list)
    federation_state:str='standalone'
    connection_state:ConnectionState=ConnectionState.NOT_TESTED
    connection_route: Optional[str]=None
    error: Optional[str]=None
    metadata:dict[str,Any]=field(default_factory=dict)

@dataclass
class DiscoveryResult:
    target_type:TargetType
    portal:Optional[TargetContext]=None
    servers:list[TargetContext]=field(default_factory=list)
    @property
    def connected_count(self):
      items=([self.portal] if self.portal else [])+self.servers
      return sum(1 for i in items if i and i.connection_state==ConnectionState.CONNECTED)
