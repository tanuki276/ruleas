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
    from ruleas.migrate import migrate
    migrate(engine)
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


def test_login_limits(client, monkeypatch):
    c, sessions = client
    import ruleas.server as server
    from ruleas.storage import LoginBucket
    monkeypatch.setattr(server.time, 'time', lambda: 6000)
    calls = []
    original = server.verify_password
    monkeypatch.setattr(server, 'verify_password', lambda *args: (calls.append(1), original(*args))[1])
    for _ in range(10):
        assert c.post('/v1/login', json={'username':'admin','password':'wrong'}).status_code == 401
    r = c.post('/v1/login', json={'username':'admin','password':'a-strong-password'})
    assert r.status_code == 429 and r.headers['Retry-After'] == '60'
    assert len(calls) == 10  # rejection precedes expensive hashing
    # Different names cannot evade the IP budget.
    for n in range(19):
        assert c.post('/v1/login', json={'username':str(n),'password':'wrong'}).status_code == 401
    assert c.post('/v1/login', json={'username':'other','password':'wrong'}).status_code == 429
    monkeypatch.setattr(server.time, 'time', lambda: 6060)
    login(c)
    # Another app/worker uses the same persisted counters.
    with sessions() as db:
        assert db.query(LoginBucket).count() > 0


def test_input_bounds_and_cache(client, monkeypatch):
    c, _ = client
    login(c)
    p = c.post('/v1/rules', json={'name':'cache','source':SOURCE}).json()
    pid = p['id']
    assert c.post('/v1/rules',json={'name':'tags','source':SOURCE,'tags':['x']*33}).status_code == 422
    assert c.post('/v1/rules',json={'name':'tags','source':SOURCE,'tags':['界'*22]}).status_code == 422
    assert c.post('/v1/rules',json={'name':'bytes','source':'#'+'界'*90000}).status_code == 422
    assert c.post('/v1/decide',content=b'x'*(1048576+1)).status_code == 413
    body = dict(policy_id=pid, rule='demo.adult', context={'age':20})
    assert c.post('/v1/decide',json=dict(body,context={'x':'a'*65536})).status_code == 422
    assert c.post('/v1/decide',json=dict(body,context={'x':[1]*4096})).status_code == 422
    deep = {}
    for _ in range(34):
        deep = {'x':deep}
    assert c.post('/v1/decide',json=dict(body,context=deep)).status_code == 422
    from rulea import RuleEngine
    original = RuleEngine.from_string
    compiled = []
    def compile_policy(source):
        compiled.append(source)
        return original(source)
    monkeypatch.setattr(RuleEngine,'from_string',compile_policy)
    for _ in range(3):
        assert c.post('/v1/decide',json=body).json()['result'] == 'ALLOW'
    assert len(compiled) == 1
    updated = dict(name='cache',source=SOURCE.replace('18','21'),expected_version=1)
    assert c.put(f'/v1/rules/{pid}',json=updated).status_code == 200
    assert c.post('/v1/decide',json=body).json()['result'] == 'DENY'
    assert c.post(f'/v1/rules/{pid}/rollback/1').status_code == 200
    assert c.post('/v1/decide',json=body).json()['result'] == 'ALLOW'


def test_streamed_body_limit(client):
    c, _ = client
    # No Content-Length; enforce the actual bytes too.
    response = c.post('/v1/login', content=(b'x'*400000 for _ in range(3)))
    assert response.status_code == 413


def test_json_decoder_depth_limit(client):
    c, _ = client
    r = c.post('/v1/decide',content=b'{"x":'*2000+b'0'+b'}'*2000,headers={'Content-Type':'application/json'})
    assert r.status_code == 422


def test_cache_evicts():
    from ruleas.limits import EngineCache
    from types import SimpleNamespace
    cache = EngineCache(capacity=2)
    for version in range(4):
        cache.get(SimpleNamespace(id=1, version=version, source=SOURCE))
    assert list(cache.entries) == [(1,2),(1,3)]
