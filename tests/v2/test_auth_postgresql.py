"""Authentication concurrency, shared rate limits and HTTP status regressions."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from rulease.config import Settings
from rulease.models import APIKey, AuthSession, Environment, Human, LoginBucket, ServiceAccount, now
from rulease.rate_limit import RateLimited, consume_login_budget
from rulease.security import (Unauthenticated, authenticate_human, authenticate_key, hash_password,
    issue_key, issue_session, logout_all_sessions, rotate_session, touch_activity)
from rulease.service import PolicyService
from test_foundation import seed, SOURCE
from test_postgresql import database, URL

pytestmark = pytest.mark.skipif(not URL, reason='Requires real PostgreSQL')


def credentials(sessions):
    with sessions.begin() as session:
        workspace, owner, reviewer = seed(session)
        owner.password_hash = hash_password('correct horse battery staple')
        account = session.scalar(select(ServiceAccount))
        key, plaintext = issue_key(session, service_account_id=account.id, human_id=owner.id,
            permissions=['decision:execute'], scope={}, expires_at=now() + timedelta(days=1))
        token = issue_session(session, owner.id)
        session.flush()
        human_session = session.scalar(select(AuthSession))
        return dict(workspace=workspace.id, human=owner.id, reviewer=reviewer.id, account=account.id,
                    key=key.id, session=human_session.id, key_token=plaintext, session_token=token)


def settings(**kwargs):
    return Settings(database_url=URL, secret_key='x'*32, **kwargs)


def app_for(database, monkeypatch, **kwargs):
    import rulease.server as server
    engine, sessions = database
    monkeypatch.setattr(server, 'connect', lambda _: (engine, sessions))
    return server.create_app(settings(**kwargs))


def test_auth_reads_do_not_wait_for_locked_credential_rows(database):
    engine, sessions = database
    c = credentials(sessions)
    old = now() - timedelta(minutes=5)
    with engine.begin() as connection:
        connection.execute(update(APIKey).values(last_used_at=old))
        connection.execute(update(AuthSession).values(last_used_at=old))
    with engine.begin() as holder:
        holder.execute(select(APIKey).with_for_update()).all()
        holder.execute(select(AuthSession).with_for_update()).all()
        def authenticate(_):
            with sessions.begin() as session:
                session.execute(text("SET LOCAL statement_timeout = '500ms'"))
                authenticate_key(session, c['key_token'], permission='decision:execute', resource={})
                authenticate_human(session, c['session_token'])
                assert not session.dirty
            touch_activity(sessions, 'key', c['key'])
            touch_activity(sessions, 'session', c['session'])
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(authenticate, range(8)))
    with sessions() as session:
        assert session.get(APIKey, c['key']).last_used_at == old
        assert session.get(AuthSession, c['session']).last_used_at == old


def test_activity_writes_are_coalesced_and_cannot_revive_revoked_tokens(database):
    engine, sessions = database
    c = credentials(sessions)
    with engine.begin() as connection:
        connection.execute(update(APIKey).values(last_used_at=now()-timedelta(minutes=5)))
        connection.execute(update(AuthSession).values(last_used_at=now()-timedelta(minutes=5)))
        connection.exec_driver_sql('''CREATE TABLE activity_writes(kind text);
          CREATE FUNCTION count_activity() RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN INSERT INTO activity_writes VALUES (TG_TABLE_NAME); RETURN NEW; END $$;
          CREATE TRIGGER key_activity AFTER UPDATE OF last_used_at ON api_keys FOR EACH ROW EXECUTE FUNCTION count_activity();
          CREATE TRIGGER session_activity AFTER UPDATE OF last_used_at ON auth_sessions FOR EACH ROW EXECUTE FUNCTION count_activity();''')
    def touch(_):
        touch_activity(sessions, 'key', c['key'])
        touch_activity(sessions, 'session', c['session'])
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(touch, range(20)))
    with engine.begin() as connection:
        assert connection.execute(text('SELECT count(*) FROM activity_writes')).scalar_one() == 2
        connection.execute(update(APIKey).values(revoked_at=now(), last_used_at=now()-timedelta(minutes=5)))
        connection.execute(update(AuthSession).values(revoked_at=now(), last_used_at=now()-timedelta(minutes=5)))
    touch(0)
    with sessions() as session:
        assert session.get(APIKey, c['key']).revoked_at
        assert session.get(AuthSession, c['session']).revoked_at
        with pytest.raises(Unauthenticated):
            authenticate_key(session, c['key_token'])
        with pytest.raises(Unauthenticated):
            authenticate_human(session, c['session_token'])


def test_concurrent_session_rotation_has_one_winner_and_preserves_absolute_expiry(database):
    _, sessions = database
    c = credentials(sessions)
    barrier = Barrier(2)
    with sessions() as session:
        expiry = session.get(AuthSession, c['session']).expires_at
    def rotate(_):
        try:
            with sessions.begin() as session:
                record = authenticate_human(session, c['session_token'])
                barrier.wait(timeout=5)
                return rotate_session(session, record)
        except Unauthenticated:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        tokens = list(pool.map(rotate, range(2)))
    assert sum(t is not None for t in tokens) == 1
    with sessions() as session:
        assert authenticate_human(session, next(t for t in tokens if t)).expires_at == expiry
        with pytest.raises(Unauthenticated):
            authenticate_human(session, c['session_token'])


def test_logout_all_wins_against_inflight_rotation(database):
    _, sessions = database
    c = credentials(sessions)
    barrier = Barrier(2)
    def operation(rotate):
        try:
            with sessions.begin() as session:
                record = authenticate_human(session, c['session_token'])
                barrier.wait(timeout=5)
                if rotate:
                    rotate_session(session, record)
                else:
                    logout_all_sessions(session, record)
        except Unauthenticated:
            assert rotate
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(operation, [True, False]))
    with sessions() as session:
        assert not session.scalars(select(AuthSession).where(AuthSession.revoked_at.is_(None))).all()


def test_ip_budget_is_atomic_across_connections_and_username_changes(database):
    _, sessions = database
    config = settings(login_ip_limit=5, login_username_limit=100)
    def attempt(i):
        try:
            consume_login_budget(sessions, config, '192.0.2.1', 'username-' + str(i))
            return True
        except RateLimited as exc:
            assert 1 <= exc.retry_after <= config.login_window_seconds
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(20))) == 5
    # Another IP has its own budget; the DB is authoritative across replicas.
    consume_login_budget(sessions, config, '192.0.2.2', 'another-user')
    with sessions.begin() as session:
        session.execute(update(LoginBucket).values(reset_at=now()-timedelta(seconds=1)))
    assert attempt(100)


def test_username_budget_is_shared_across_ips(database):
    _, sessions = database
    config = settings(login_ip_limit=100, login_username_limit=2)
    consume_login_budget(sessions, config, '192.0.2.1', 'owner')
    consume_login_budget(sessions, config, '192.0.2.2', 'owner')
    with pytest.raises(RateLimited):
        consume_login_budget(sessions, config, '192.0.2.3', 'owner')


def test_http_ip_limit_runs_before_password_hashing_and_ignores_untrusted_forwarding(database, monkeypatch):
    import rulease.server as server
    app = app_for(database, monkeypatch, login_ip_limit=2, login_username_limit=100)
    calls = []
    monkeypatch.setattr(server, 'verify_password', lambda *args: (calls.append(1) or False, None))
    with TestClient(app, client=('192.0.2.1', 5000)) as client:
        for i in range(3):
            result = client.post('/v2/auth/login', json={'username': 'user' + str(i), 'password': 'incorrect'},
                                 headers={'X-Forwarded-For': '198.51.100.' + str(i)})
            assert result.status_code == (401 if i < 2 else 429)
        assert int(result.headers['retry-after']) > 0
        assert result.headers['content-type'].startswith('application/problem+json')
    assert len(calls) == 2
    with TestClient(app, client=('192.0.2.2', 5000)) as client:
        assert client.post('/v2/auth/login', json={'username': 'other', 'password': 'incorrect'}).status_code == 401


@pytest.mark.parametrize('kind,state', [('key','unknown'), ('key','expired'), ('key','revoked'),
    ('key','disabled'), ('session','unknown'), ('session','expired'), ('session','idle'), ('session','revoked')])
def test_invalid_credentials_are_401_with_challenge(database, monkeypatch, kind, state):
    _, sessions = database
    c = credentials(sessions)
    with sessions.begin() as session:
        row = session.get(APIKey if kind == 'key' else AuthSession, c[kind])
        if state == 'expired':
            row.expires_at = now() - timedelta(seconds=1)
        elif state == 'revoked':
            row.revoked_at = now()
        elif state == 'idle':
            row.last_used_at = now()-timedelta(minutes=31)
        elif state == 'disabled':
            session.get(ServiceAccount, c['account']).enabled = False
    app = app_for(database, monkeypatch)
    token = (('rk_' if kind == 'key' else 'rhs_') + 'a'*43) if state == 'unknown' else c[kind + '_token']
    with TestClient(app) as client:
        headers = {'Authorization': 'Bearer ' + token, 'X-Rulease-Workspace': 'team'}
        result = (client.post('/v2/decisions', headers=headers,
            json={'project':'commerce','policy':'checkout','rule':'discount','context':{}}) if kind == 'key' else
            client.get('/v2/projects/commerce/policies', headers=headers))
        assert result.status_code == 401, result.text
        assert result.headers['www-authenticate'] == 'Bearer realm="rulease"'


def test_authenticated_but_unauthorized_is_403(database, monkeypatch):
    _, sessions = database
    c = credentials(sessions)
    with sessions.begin() as session:
        reviewer_token = issue_session(session, c['reviewer'])
        session.get(APIKey, c['key']).permissions = ['policy:read']
    app = app_for(database, monkeypatch)
    with TestClient(app) as client:
        response = client.post('/v2/projects/commerce/policies', json={'key':'denied','name':'Denied','source':SOURCE},
            headers={'Authorization':'Bearer '+reviewer_token,'X-Rulease-Workspace':'team'})
        assert response.status_code == 403 and 'www-authenticate' not in response.headers
        response = client.post('/v2/decisions', json={'project':'commerce','policy':'checkout','rule':'discount','context':{}},
            headers={'Authorization':'Bearer '+c['key_token'],'X-Rulease-Workspace':'team'})
        assert response.status_code == 403 and 'www-authenticate' not in response.headers


def test_commit_time_tenant_violation_is_409_before_response_and_rolls_back(database, monkeypatch):
    import rulease.server as server
    from rulease.models import DecisionEvent, Workspace
    _, sessions = database
    c = credentials(sessions)
    with sessions.begin() as session:
        other = Workspace(key='other', name='Other')
        session.add(other)
        svc = PolicyService(session, c['workspace'], c['human'])
        session.scalar(select(Environment)).required_approvals = 0
        svc.create_policy('commerce','checkout','Checkout',SOURCE)
        svc.commit('commerce','checkout',1)
        d = svc.create_deployment('commerce','production',{'checkout':1},1)
        svc.release(d.id)
        session.flush()
        other_id = other.id
    real_decide = server.decide
    def corrupt_event(session, **kwargs):
        result = real_decide(session, **kwargs)
        next(row for row in session.new if isinstance(row, DecisionEvent)).workspace_id = other_id
        return result
    monkeypatch.setattr(server, 'decide', corrupt_event)
    app = app_for(database, monkeypatch)
    with TestClient(app) as client:
        response = client.post('/v2/decisions', json={'project':'commerce','policy':'checkout','rule':'discount','context':{'amount':9000}},
            headers={'Authorization':'Bearer '+c['key_token'],'X-Rulease-Workspace':'team'})
        assert response.status_code == 409, response.text
        assert response.headers['content-type'].startswith('application/problem+json')
    with sessions() as session:
        assert not session.scalars(select(DecisionEvent)).all()


def test_valid_credentials_cannot_cross_workspaces(database, monkeypatch):
    from rulease.models import Workspace
    _, sessions = database
    c = credentials(sessions)
    with sessions.begin() as session:
        session.add(Workspace(key='other', name='Other'))
    app = app_for(database, monkeypatch)
    with TestClient(app) as client:
        response = client.get('/v2/projects/commerce/policies',
            headers={'Authorization':'Bearer '+c['session_token'],'X-Rulease-Workspace':'other'})
        assert response.status_code == 403
        response = client.post('/v2/decisions', json={'project':'commerce','policy':'checkout','rule':'discount','context':{}},
            headers={'Authorization':'Bearer '+c['key_token'],'X-Rulease-Workspace':'other'})
        assert response.status_code == 403
