import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from rulease.config import Settings
from rulease.rate_limit import client_ip
from rulease.server import create_app


def request(peer, forwarded=None):
    headers = [(b'x-forwarded-for', forwarded.encode())] if forwarded else []
    return Request({'type': 'http', 'client': (peer, 1234), 'headers': headers})


@pytest.mark.parametrize('peer,forwarded,trusted,expected', [
    ('192.0.2.5', '198.51.100.1', [], '192.0.2.5'),
    ('192.0.2.5', '198.51.100.1', ['10.0.0.0/8'], '192.0.2.5'),
    ('10.0.0.2', '198.51.100.1, 10.0.0.1', ['10.0.0.0/8'], '198.51.100.1'),
    ('10.0.0.2', '203.0.113.9, 192.0.2.5', ['10.0.0.0/8'], '192.0.2.5'),
    ('10.0.0.2', 'invalid', ['10.0.0.0/8'], '10.0.0.2'),
    ('::ffff:192.0.2.5', None, [], '192.0.2.5'),
    ('2001:0db8:0:0::1', None, [], '2001:db8::1'),
])
def test_client_ip_trust_boundary(peer, forwarded, trusted, expected):
    assert client_ip(request(peer, forwarded), trusted) == expected


def test_invalid_proxy_config_is_rejected():
    with pytest.raises(ValueError):
        Settings(database_url='postgresql://localhost/test', secret_key='x'*32, trusted_proxies=['*'])


@pytest.mark.parametrize('headers', [{}, {'Authorization': 'Basic abc'},
    {'Authorization': 'Bearer'}, {'Authorization': 'Bearer invalid'},
    {'Authorization': 'Bearer rk_' + 'a'*43}])
def test_management_missing_invalid_or_wrong_kind_is_401_before_workspace_lookup(headers):
    app = create_app(Settings(database_url='postgresql://localhost/test', secret_key='x'*32))
    try:
        with TestClient(app) as client:
            result = client.get('/v2/projects/commerce/policies', headers=headers)
            assert result.status_code == 401
            assert result.headers['www-authenticate'] == 'Bearer realm="rulease"'
            assert result.headers['content-type'].startswith('application/problem+json')
    finally:
        app.state.engine.dispose()


@pytest.mark.parametrize('authorization', ['', 'Bearer invalid', 'Bearer rhs_' + 'a'*43])
def test_machine_authentication_precedes_workspace_lookup(authorization):
    app = create_app(Settings(database_url='postgresql://localhost/test', secret_key='x'*32))
    try:
        with TestClient(app) as client:
            result = client.post('/v2/decisions', headers={'Authorization': authorization},
                json={'project': 'commerce', 'policy': 'checkout', 'rule': 'discount', 'context': {}})
            assert result.status_code == 401
            assert 'www-authenticate' in result.headers
    finally:
        app.state.engine.dispose()
