import pytest
from fastapi.testclient import TestClient
from ruleas.server import create_app
from ruleas.storage import Base, User, Audit, connect
from ruleas.security import hash_password

SOURCE = 'namespace demo\nversion 1\nrule adult:\n    when: age >= 18\n    reason: "Too young"\n'
@pytest.fixture
def client(tmp_path):
    url = 'sqlite:///' + str(tmp_path / 'test.db')
    engine, sessions = connect(url)
    Base.metadata.create_all(engine)
    with sessions() as db:
        for name, role in [('admin','admin'), ('viewer','viewer')]:
            db.add(User(username=name, role=role, password=hash_password('a-strong-password')))
        db.commit()
    with TestClient(create_app(url, 's'*32, secure_cookie=False)) as c:
        yield c, sessions
    engine.dispose()

def login(c, name='admin'):
    r = c.post('/v1/login', json={'username':name, 'password':'a-strong-password'})
    assert r.status_code == 200
    c.headers['X-CSRF-Token'] = r.json()['csrf_token']

def test_lifecycle(client):
    c, sessions = client
    assert c.get('/health').status_code == 200
    assert c.get('/v1/rules').status_code == 401
    login(c)
    payload = dict(name='test', source=SOURCE, tags=['auth'])
    r = c.post('/v1/rules', json=payload)
    assert r.status_code == 201, r.text
    p = r.json()
    assert p['namespace'] == 'demo'
    pid = p['id']
    for age, result in [(20,'ALLOW'),(10,'DENY'),('bad','ERROR')]:
        d = c.post('/v1/decide', json=dict(policy_id=pid, rule='demo.adult', context={'age':age})).json()
        assert d['result'] == result
        assert d['policy_hash'] and d['engine_version'] and 'trace' in d
    assert c.post('/v1/check', json=dict(policy_id=pid, rule='demo.adult', context={'age':10})).json()['allowed'] is False
    assert c.put(f'/v1/rules/{pid}', json=payload).status_code == 409
    payload.update(enabled=False, expected_version=1)
    assert c.put(f'/v1/rules/{pid}', json=payload).json()['version'] == 2
    assert c.post('/v1/decide', json=dict(policy_id=pid, rule='demo.adult', context={})).json()['result'] == 'NOT_APPLICABLE'
    assert c.post(f'/v1/rules/{pid}/rollback/1').json()['version'] == 3
    assert len(c.get(f'/v1/rules/{pid}/versions').json()) == 3
    assert c.get(f'/v1/rules/{pid}/source').text == SOURCE
    assert c.get('/v1/audit-logs').json()[0]['actor'] == 'admin'
    assert c.delete(f'/v1/rules/{pid}').status_code == 200
    assert c.get(f'/v1/rules/{pid}').status_code == 404
    assert c.post(f'/v1/rules/{pid}/rollback/1').status_code == 200

def test_auth_and_validation(client):
    c, _ = client
    login(c)
    csrf = c.headers.pop('X-CSRF-Token')
    assert c.post('/v1/api-keys', json={'name':'x'}).status_code == 403
    c.headers['X-CSRF-Token'] = csrf
    assert c.post('/v1/rules',json={'name':'bad','source':'invalid'}).status_code == 422
    key = c.post('/v1/api-keys',json={'name':'test'}).json()
    assert key['key'].startswith('rs_')
    assert 'digest' not in c.get('/v1/api-keys').text
    c.cookies.clear()
    c.headers['Authorization'] = 'Bearer '+key['key']
    assert c.get('/v1/rules').status_code == 200
    assert c.delete('/v1/api-keys/'+str(key['id'])).status_code == 200
    assert c.get('/v1/rules').status_code == 401
    del c.headers['Authorization']
    login(c, 'viewer')
    assert c.get('/v1/rules').status_code == 200
    assert c.post('/v1/rules', json={'name':'x','source':SOURCE}).status_code == 403
    assert c.get('/v1/audit-logs').status_code == 403
    assert c.get('/').status_code == 200
