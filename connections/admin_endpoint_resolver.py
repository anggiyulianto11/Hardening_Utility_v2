from core.models import ConnectionRoute
class ResolvedAdminEndpoint:
    def __init__(self,url,route):
      self.effective_admin_url=url; self.route=route

def resolve(service_url,registered_admin_url,probe):
    su=f"{service_url.rstrip('/')}/admin"
    if probe(su):
      return ResolvedAdminEndpoint(su,ConnectionRoute.SERVICE_URL)
    ru=f"{registered_admin_url.rstrip('/')}/admin"
    if probe(ru):
      return ResolvedAdminEndpoint(ru,ConnectionRoute.REGISTERED_ADMIN_URL)
    raise RuntimeError('No admin endpoint reachable')
