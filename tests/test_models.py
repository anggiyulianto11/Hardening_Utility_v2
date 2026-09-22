from core.models import *

def test_connected_count():
 t=TargetContext("1","a","server","enterprise",connection_state=ConnectionState.CONNECTED)
 d=DiscoveryResult(TargetType.ENTERPRISE,servers=[t])
 assert d.connected_count==1
