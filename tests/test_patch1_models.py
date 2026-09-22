from core.models import TargetContext

def test_patch1_fields():
 t=TargetContext("1","n","server","enterprise")
 assert hasattr(t,"effective_admin_url")
