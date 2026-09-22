from connections.admin_endpoint_resolver import resolve
from core.models import ConnectionRoute

def test_service_first():
 r=resolve('https://a/server','https://b:6443/arcgis',lambda u:'a/server/admin' in u)
 assert r.route==ConnectionRoute.SERVICE_URL

def test_fallback():
 r=resolve('https://a/server','https://b:6443/arcgis',lambda u:'b:6443' in u)
 assert r.route==ConnectionRoute.REGISTERED_ADMIN_URL
