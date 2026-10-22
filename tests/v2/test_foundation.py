import base64
import hashlib
import os
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from rulease.config import Settings
from rulease.database import connect
from rulease.models import (Base, Deployment, Draft, Environment, Human, Membership, Policy,
                            Project, Release, Revision, ServiceAccount, Workspace)
from rulease.security import hash_password, verify_password
from rulease.service import Conflict, Forbidden, PolicyService, ROLE_PERMISSIONS, decide, preview

SOURCE = 'rule discount:\n    when: amount >= 10000\n    reason: minimum_total\n'


def seed(session):
    workspace, user, reviewer = Workspace(key='team', name='Team'), Human(username='owner'), Human(username='reviewer')
    session.add_all([workspace, user, reviewer])
    session.flush()
    project = Project(workspace_id=workspace.id, key='commerce', name='Commerce')
    session.add(project)
    session.flush()
    session.add_all([Membership(workspace_id=workspace.id, human_id=user.id, permissions=sorted(ROLE_PERMISSIONS['owner'])),
        Membership(workspace_id=workspace.id, human_id=reviewer.id, permissions=sorted(ROLE_PERMISSIONS['reviewer'])),
        Environment(project_id=project.id, key='production', required_approvals=1),
        ServiceAccount(workspace_id=workspace.id, name='checkout-api')])
    session.flush()
    return workspace, user, reviewer


def exercise_lifecycle(session):
    workspace, user, reviewer = seed(session)
    svc = PolicyService(session, workspace.id, user.id)
    _, draft = svc.create_policy('commerce', 'checkout', 'Checkout', SOURCE)
    first = svc.commit('commerce', 'checkout', 1)
    assert session.scalar(select(Release)) is None
    account = session.scalar(select(ServiceAccount))
    args = dict(workspace_id=workspace.id, service_account_id=account.id, project_key='commerce',
                policy_key='checkout', environment='production', rule='discount', context={'amount': 9000})
    with pytest.raises(LookupError):
        decide(session, **args)
    deployment = svc.create_deployment('commerce', 'production', {'checkout': 1}, 1)
    with pytest.raises(Forbidden):
        svc.approve(deployment.id)
    with pytest.raises(Conflict):
        svc.release(deployment.id)
    PolicyService(session, workspace.id, reviewer.id).approve(deployment.id)
    svc.release(deployment.id)
    assert decide(session, **args)['result'] == 'DENY'
    svc.save_draft('commerce', 'checkout', SOURCE.replace('10000', '8000'), {}, 1)
    with pytest.raises(Conflict):
        svc.save_draft('commerce', 'checkout', SOURCE, {}, 1)
    assert decide(session, **args)['result'] == 'DENY'
    second = svc.commit('commerce', 'checkout', 2)
    assert second.number == 2 and first.source == SOURCE
    assert decide(session, **args)['revision'] == 1
    deployment = svc.create_deployment('commerce', 'production', {'checkout': 2}, 2)
    PolicyService(session, workspace.id, reviewer.id).approve(deployment.id)
    svc.release(deployment.id)
    assert decide(session, **args)['result'] == 'ALLOW'
    rollback = svc.rollback('commerce', 'production', {'checkout': 1}, 3)
    PolicyService(session, workspace.id, reviewer.id).approve(rollback.id)
    svc.release(rollback.id)
    assert decide(session, **args)['revision'] == 1
    assert len(session.scalars(select(Revision)).all()) == 2
    other = Workspace(key='other', name='Other')
    session.add(other)
    session.flush()
    with pytest.raises(Forbidden):
        PolicyService(session, other.id, user.id).commit('commerce', 'checkout', 2)


def test_transactional_service_with_test_only_in_memory_adapter():
    # This does not test PostgreSQL constraints/locks. Production connect() rejects SQLite.
    engine = create_engine('sqlite://')
    Base.metadata.create_all(engine)
    with Session(engine) as session, session.begin():
        exercise_lifecycle(session)
    engine.dispose()


def test_preview_and_config_are_database_free():
    assert preview(SOURCE, 'discount', {'amount': 9000})['result'] == 'DENY'
    assert preview(SOURCE, 'discount', {'amount': 11000}, trace='none')['trace'] == []
    with pytest.raises(ValueError):
        Settings(database_url='sqlite://', secret_key='x'*32)
    with pytest.raises(ValueError):
        connect('sqlite://')
    with pytest.raises(ValueError):
        Settings(database_url='postgresql://localhost/db', secret_key='short')
    with pytest.raises(ValueError):
        Settings(database_url='postgresql://localhost/db', secret_key='x'*32, production=True)


def test_argon2_and_legacy_scrypt_rehash():
    encoded = hash_password('correct horse battery staple')
    assert encoded.startswith('$argon2id$')
    assert verify_password('correct horse battery staple', encoded) == (True, None)
    assert verify_password('incorrect', encoded) == (False, None)
    salt = b'1234567890123456'
    old = base64.b64encode(salt + hashlib.scrypt(b'legacy-password', salt=salt, n=16384, r=8, p=1)).decode()
    valid, replacement = verify_password('legacy-password', old)
    assert valid and replacement.startswith('$argon2id$')
    assert verify_password('incorrect', old) == (False, None)
    assert verify_password('incorrect', 'not a hash') == (False, None)


def test_cli_diff_direction_and_openapi(tmp_path, capsys):
    import json
    from rulease.cli import main
    from rulease.server import create_app
    baseline, candidate = tmp_path/'baseline.rulea', tmp_path/'candidate.rulea'
    baseline.write_text(SOURCE)
    candidate.write_text(SOURCE.replace('10000', '8000'))
    assert main(['diff', str(candidate), '--against', str(baseline)]) == 0
    change = json.loads(capsys.readouterr().out)['semantic'][0]
    assert change['before'] == 'amount >= 10000'
    assert change['after'] == 'amount >= 8000'
    settings = Settings(database_url='postgresql://localhost/test', secret_key='x'*32)
    app = create_app(settings)
    try:
        schema = app.openapi()
        assert '/v2/decisions' in schema['paths']
        assert '/v2/decisions/batch' in schema['paths']
        assert '/health/ready' in schema['paths']
        assert 'policy_id' not in schema['components']['schemas']['DecisionInput']['properties']
    finally:
        app.state.engine.dispose()
