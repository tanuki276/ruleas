"""Run against a real PostgreSQL service when RULEAS_TEST_DATABASE_URL is set."""
import os
import pytest
from fastapi.testclient import TestClient
from ruleas.storage import Base, User, Policy, connect
from ruleas.migrate import migrate
from sqlalchemy import select, text
from concurrent.futures import ThreadPoolExecutor
from ruleas.security import hash_password
from ruleas.server import create_app

@pytest.mark.skipif(not os.getenv('RULEAS_TEST_DATABASE_URL'), reason='PostgreSQL test URL not configured')
def test_postgres_roundtrip():
    url = os.environ['RULEAS_TEST_DATABASE_URL']
    engine, sessions = connect(url)
    migrate(engine)
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
            # Evaluation and GET must finish while another transaction holds the
            # row lock used by policy writers. A FOR UPDATE regression times out.
            with engine.connect() as locker, ThreadPoolExecutor(max_workers=1) as executor:
                transaction = locker.begin()
                locker.execute(select(Policy).where(Policy.id == pid).with_for_update())
                try:
                    for path, method, body in [
                        (f'/v1/rules/{pid}', 'GET', None),
                        (f'/v1/rules/{pid}/source', 'GET', None),
                        ('/v1/decide', 'POST', {'policy_id':pid,'rule':'yes','context':{}}),
                        ('/v1/check', 'POST', {'policy_id':pid,'rule':'yes','context':{}}),
                    ]:
                        future = executor.submit(c.request, method, path, json=body)
                        assert future.result(timeout=3).status_code == 200
                finally:
                    transaction.rollback()
            assert c.post(f'/v1/rules/{pid}/rollback/1').json()['version'] == 2
            assert c.get('/v1/audit-logs').status_code == 200
    finally:
        Base.metadata.drop_all(engine)
        with engine.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS alembic_version"))
        engine.dispose()
