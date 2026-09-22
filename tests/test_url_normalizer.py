import pytest
from core.url_normalizer import normalize_portal_url, normalize_server_url


def test_portal_base_url():
    result = normalize_portal_url("https://example.com/portal")
    assert result["portal_admin"] == "https://example.com/portal/portaladmin"
    assert result["sharing_rest"] == "https://example.com/portal/sharing/rest"


def test_portal_admin_url_is_accepted():
    result = normalize_portal_url("https://example.com/portal/portaladmin")
    assert result["base"] == "https://example.com/portal"


def test_server_admin_url_is_accepted():
    result = normalize_server_url("https://example.com/server/admin")
    assert result["base"] == "https://example.com/server"


def test_http_is_rejected():
    with pytest.raises(ValueError):
        normalize_portal_url("http://example.com/portal")
