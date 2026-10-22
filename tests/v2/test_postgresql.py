"""Run against a disposable schema in a real PostgreSQL database."""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from rulease.database import migrate
from rulease.models import (APIKey, DeploymentItem, Environment, Human, Membership, Policy,
                            Project, Release, Revision, ServiceAccount, Workspace, now)
from rulease.security import hash_password, issue_key
from rulease.service import Conflict, PolicyService, ROLE_PERMISSIONS
from test_foundation import SOURCE, exercise_lifecycle, seed

URL = os.getenv('RULEASE_TEST_DATABASE_URL')
pytestmark = pytest.mark.skipif(not URL, reason='RULEASE_TEST_DATABASE_URL requires a real PostgreSQL database')


@pytest.fixture
def database(request):
    url = make_url(URL).set(drivername='postgresql+psycopg')
    admin = create_engine(url)
    name = 'v2_test_' + uuid4().hex
    with admin.begin() as connection:
        connection.exec_driver_sql('CREATE SCHEMA ' + name)
    engine = create_engine(url, connect_args={'options': '-csearch_path=' + name})
    try:
        if getattr(request, 'param', None) == 'initial':
            import hashlib
            from importlib.resources import files
            sql = files('rulease').joinpath('migrations/0001.sql').read_text()
            with engine.begin() as connection:
                connection.exec_driver_sql('CREATE TABLE rulease_migrations (version text PRIMARY KEY, checksum text NOT NULL)')
                connection.exec_driver_sql(sql, execution_options={'no_parameters': True})
                connection.execute(text('INSERT INTO rulease_migrations VALUES (:version, :checksum)'),
                    {'version': '0001.sql', 'checksum': hashlib.sha256(sql.encode()).hexdigest()})
        else:
            migrate(engine)
            migrate(engine)  # Ordered migration must be repeatable without touching history.
        yield engine, sessionmaker(engine, expire_on_commit=False)
    finally:
        engine.dispose()
        with admin.begin() as connection:
            connection.exec_driver_sql('DROP SCHEMA ' + name + ' CASCADE')
        admin.dispose()


def test_full_lifecycle_on_postgresql(database):
    _, sessions = database
    with sessions.begin() as session:
        exercise_lifecycle(session)


def test_database_rejects_revision_mutation_and_policy_key_change(database):
    engine, sessions = database
    with sessions.begin() as session:
        workspace, owner, _ = seed(session)
        svc = PolicyService(session, workspace.id, owner.id)
        svc.create_policy('commerce', 'checkout', 'Checkout', SOURCE)
        revision = svc.commit('commerce', 'checkout', 1)
        revision_id = revision.id
    for sql, params in [
        ('UPDATE revisions SET source = :value WHERE id = :id', {'value': 'tampered', 'id': revision_id}),
        ('DELETE FROM revisions WHERE id = :id', {'id': revision_id}),
        ("UPDATE policies SET key = 'renamed'", {}),
    ]:
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(text(sql), params)


def test_competing_releases_use_compare_and_swap(database):
    _, sessions = database
    with sessions.begin() as session:
        workspace, owner, _ = seed(session)
        svc = PolicyService(session, workspace.id, owner.id)
        env = session.scalar(select(Environment))
        env.required_approvals = 0
        svc.create_policy('commerce', 'checkout', 'Checkout', SOURCE)
        svc.commit('commerce', 'checkout', 1)
        first = svc.create_deployment('commerce', 'production', {'checkout': 1}, 1)
        second = svc.create_deployment('commerce', 'production', {'checkout': 1}, 1)
        ids, workspace_id, owner_id = [first.id, second.id], workspace.id, owner.id
    def release(identifier):
        try:
            with sessions.begin() as session:
                PolicyService(session, workspace_id, owner_id).release(identifier)
            return 'released'
        except Conflict:
            return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(release, ids)) == ['conflict', 'released']
    with sessions() as session:
        assert len(session.scalars(select(Release)).all()) == 1


def test_bad_bundle_rolls_back_all_releases(database):
    _, sessions = database
    with sessions.begin() as session:
        workspace, owner, _ = seed(session)
        session.scalar(select(Environment)).required_approvals = 0
        svc = PolicyService(session, workspace.id, owner.id)
        for key in ['checkout', 'shipping']:
            svc.create_policy('commerce', key, key, SOURCE)
            svc.commit('commerce', key, 1)
        deployment = svc.create_deployment('commerce', 'production', {'checkout': 1, 'shipping': 1}, 1)
        deployment_id, workspace_id, owner_id = deployment.id, workspace.id, owner.id
        session.scalar(select(Policy).where(Policy.key == 'shipping')).archived = True
    with pytest.raises(Conflict), sessions.begin() as session:
        PolicyService(session, workspace_id, owner_id).release(deployment_id)
    with sessions() as session:
        assert session.scalar(select(Release)) is None
        assert session.scalar(select(Environment)).version == 1


def test_http_auth_draft_preview_release_and_scoped_batch(database, monkeypatch):
    engine, sessions = database
    import rulease.server as server
    from rulease.config import Settings
    monkeypatch.setattr(server, 'connect', lambda _: (engine, sessions))
    with sessions.begin() as session:
        workspace, owner, _ = seed(session)
        owner.password_hash = hash_password('correct horse battery staple')
        svc = PolicyService(session, workspace.id, owner.id)
        session.scalar(select(Environment)).required_approvals = 0
        svc.create_policy('commerce', 'checkout', 'Checkout', SOURCE)
        svc.commit('commerce', 'checkout', 1)
        d = svc.create_deployment('commerce', 'production', {'checkout': 1}, 1)
        svc.release(d.id)
        account = session.scalar(select(ServiceAccount))
        _, key = issue_key(session, service_account_id=account.id, human_id=owner.id,
            permissions=['decision:execute'], scope={'project': 'commerce', 'policy': 'checkout', 'environment': 'production'},
            expires_at=now() + timedelta(days=1))
    app = server.create_app(Settings(database_url=URL, secret_key='x'*32))
    with TestClient(app) as client:
        login = client.post('/v2/auth/login', json={'username': 'owner', 'password': 'correct horse battery staple'})
        assert login.status_code == 200, login.text
        token = login.json()['session_token']
        headers = {'Authorization': 'Bearer ' + token, 'X-Rulease-Workspace': 'team'}
        path = '/v2/projects/commerce/policies/checkout/draft'
        draft = client.get(path, headers=headers)
        assert draft.headers['etag'] == '"draft-1"'
        assert client.put(path, headers=headers, json={'source': SOURCE}).status_code == 428
        saved = client.put(path, headers={**headers, 'If-Match': '"draft-1"'}, json={'source': SOURCE.replace('10000', '8000')})
        assert saved.status_code == 200, saved.text
        assert client.put(path, headers={**headers, 'If-Match': '"draft-1"'}, json={'source': SOURCE}).status_code == 412
        preview = client.post('/v2/preview', headers=headers,
            json={'source': SOURCE.replace('10000', '8000'), 'rule': 'discount', 'context': {'amount': 9000}})
        assert preview.json()['result'] == 'ALLOW'
        item = {'project': 'commerce', 'policy': 'checkout', 'rule': 'discount', 'context': {'amount': 9000}}
        machine = {'Authorization': 'Bearer ' + key, 'X-Rulease-Workspace': 'team'}
        result = client.post('/v2/decisions', headers=machine, json=item)
        assert result.status_code == 200, result.text
        assert result.json()['result'] == 'DENY'
        batch = client.post('/v2/decisions/batch', headers=machine, json={'items': [item, item]})
        assert batch.status_code == 200, batch.text
        assert len({i['decision_id'] for i in batch.json()['items']}) == 2
        assert client.post('/v2/decisions', headers=machine, json={**item, 'environment': 'staging'}).status_code == 403
        assert client.get(path, headers=machine).status_code == 401
        assert client.post('/v2/decisions', headers=headers, json=item).status_code == 401
        assert client.post('/v2/auth/logout-all', headers=headers).status_code == 204
        assert client.get(path, headers=headers).status_code == 401
