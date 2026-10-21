"""Run against a real PostgreSQL service when RULEAS_TEST_DATABASE_URL is set."""
import os
import pytest
from fastapi.testclient import TestClient
from ruleas.storage import Base, User, connect
from ruleas.security import hash_password
from ruleas.server import create_app

@pytest.mark.skipif(not os.getenv('RULEAS_TEST_DATABASE_URL'), reason='PostgreSQL test URL not configured')
def test_postgres_roundtrip():
    url = os.environ['RULEAS_TEST_DATABASE_URL']
    engine, sessions = connect(url)
    Base.metadata.create_all(engine)
    try:
        with sessions() as db:
            db.add(User(username='pgadmin', password=hash_password('postgres-test-password'), role='admin'))
            db.commit()
        with TestClient(create_app(url, 'p'*32, secure_cookie=False)) as c:
            token = c.post('/v1/login',json={'username':'pgadmin','password':'postgres-test-password'}).json()['csrf_token']
            c.headers['X-CSRF-Token'] = token
            r = c.post('/v1/rules',json={'name':'pg','source':'rule yes:\n    when: True\n'})
            assert r.status_code == 201, r.text
            pid = r.json()['id']
            assert c.post('/v1/decide',json={'policy_id':pid,'rule':'yes','context':{}}).json()['result'] == 'ALLOW'
            assert c.post(f'/v1/rules/{pid}/rollback/1').json()['version'] == 2
            assert c.get('/v1/audit-logs').status_code == 200
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
