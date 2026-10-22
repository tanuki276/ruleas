"""Reject forged parent chains through SQL, not merely through API lookup filters."""
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import insert, inspect, select, text, update
from sqlalchemy.exc import IntegrityError

from rulease.database import migrate
from rulease.models import (APIKey, ApprovalRequest, DecisionEvent, Deployment, Draft, Environment,
    Human, Membership, Policy, Project, Release, Revision, ServiceAccount, SimulationJob,
    TestRun as RunRecord, TestSuite as SuiteRecord, Workspace, now)
from rulease.security import issue_key
from rulease.service import PolicyService, ROLE_PERMISSIONS
from test_foundation import seed, SOURCE
from test_postgresql import database, URL

pytestmark = pytest.mark.skipif(not URL, reason='Requires real PostgreSQL')


def graphs(sessions):
    with sessions.begin() as session:
        workspace, owner, _ = seed(session)
        other = Workspace(key='other', name='Other')
        human = Human(username='other-owner')
        session.add_all([other, human])
        session.flush()
        session.add(Membership(workspace_id=other.id, human_id=human.id, permissions=sorted(ROLE_PERMISSIONS['owner'])))
        project = Project(workspace_id=other.id, key='commerce', name='Commerce')
        private = Project(workspace_id=other.id, key='private', name='Private')
        session.add_all([project, private])
        session.flush()
        session.add_all([Environment(project_id=project.id, key='production', required_approvals=0),
                        ServiceAccount(workspace_id=other.id, name='checkout-api')])
        session.flush()
        result = []
        for w, h in [(workspace, owner), (other, human)]:
            svc = PolicyService(session, w.id, h.id)
            p = svc.project('commerce')
            env = svc.environment(p, 'production')
            env.required_approvals = 0
            policy, draft = svc.create_policy('commerce', 'checkout', 'Checkout', SOURCE)
            revision = svc.commit('commerce', 'checkout', 1)
            second = svc.commit('commerce', 'checkout', 1)
            d = svc.create_deployment('commerce', 'production', {'checkout': 1}, 1)
            release = svc.release(d.id)[0]
            pending = svc.create_deployment('commerce', 'production', {'checkout': 1}, 2)
            suite = SuiteRecord(policy_id=policy.id, name='Regression')
            session.add(suite)
            session.flush()
            account = session.scalar(select(ServiceAccount).where(ServiceAccount.workspace_id == w.id))
            result.append(dict(workspace=w.id, human=h.id, project=p.id, environment=env.id, policy=policy.id,
                revision=revision.id, second=second.id, release=release.id, deployment=pending.id,
                suite=suite.id, account=account.id, draft=draft.id))
        return result


def event(graph):
    current = now()
    return dict(id='dec_'+uuid4().hex, created_at=current, evaluated_at=current,
        workspace_id=graph['workspace'], project_id=graph['project'], policy_id=graph['policy'],
        revision_id=graph['revision'], release_id=graph['release'], service_account_id=graph['account'],
        rule='discount', result='DENY', reason='minimum_total', input_hash='a'*64, duration_us=1)


@pytest.mark.parametrize('field,other_field', [('workspace_id','workspace'), ('project_id','project'),
    ('policy_id','policy'), ('revision_id','revision'), ('release_id','release'), ('service_account_id','account')])
def test_decision_cannot_mix_tenants(database, field, other_field):
    engine, sessions = database
    a, b = graphs(sessions)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(insert(DecisionEvent).values(**{**event(a), field:b[other_field]}))
    with engine.begin() as connection:
        connection.execute(insert(DecisionEvent).values(**event(a)))


def test_decision_revision_must_match_release_even_within_one_policy(database):
    engine, sessions = database
    a, _ = graphs(sessions)
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(insert(DecisionEvent).values(**{**event(a), 'revision_id':a['second']}))


def test_test_runs_and_simulations_cannot_mix_policies_or_tenants(database):
    engine, sessions = database
    a, b = graphs(sessions)
    with sessions.begin() as session:
        svc = PolicyService(session, a['workspace'], a['human'])
        shipping, _ = svc.create_policy('commerce', 'shipping', 'Shipping', SOURCE)
        shipping_revision = svc.commit('commerce', 'shipping', 1).id
    for candidate in [b['revision'], shipping_revision]:
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(insert(RunRecord).values(id=str(uuid4()), policy_id=a['policy'],
                suite_id=a['suite'], revision_id=candidate, report={}))
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(insert(SimulationJob).values(id=str(uuid4()), policy_id=a['policy'],
                project_id=a['project'], baseline_id=a['revision'], candidate_id=candidate))
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(insert(SimulationJob).values(id=str(uuid4()), policy_id=a['policy'],
            project_id=b['project'], baseline_id=a['revision'], candidate_id=a['second']))


@pytest.mark.parametrize('table,field,key', [(Project,'workspace_id','project'),
    (Environment,'project_id','environment'), (ServiceAccount,'workspace_id','account'),
    (Draft,'policy_id','draft'), (SuiteRecord,'policy_id','suite')])
def test_parent_resources_cannot_be_reassigned(database, table, field, key):
    engine, sessions = database
    a, b = graphs(sessions)
    other = b[{'workspace_id':'workspace','project_id':'project','policy_id':'policy'}[field]]
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(update(table).where(table.id == a[key]).values(**{field:other}))


def test_creators_reviewers_and_key_scopes_must_belong_to_resource_workspace(database):
    engine, sessions = database
    a, b = graphs(sessions)
    bad = [insert(Revision).values(id=str(uuid4()), policy_id=a['policy'], number=3, source=SOURCE,
                context_schema={}, revision_hash='a'*64, engine_version='test', created_by=b['human']),
           insert(Deployment).values(id=str(uuid4()), project_id=a['project'], environment_id=a['environment'],
                created_by=b['human'], base_version=2),
           insert(ApprovalRequest).values(id=str(uuid4()), deployment_id=a['deployment'], reviewer_id=b['human'], approved=True)]
    for statement in bad:
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(statement)
    for human, scope in [(b['human'], {}), (a['human'], {'project':'private'}),
                          (a['human'], {'project':'commerce','policy':'missing'}),
                          (a['human'], {'project':'commerce','environment':'missing'})]:
        with pytest.raises(IntegrityError), sessions.begin() as session:
            issue_key(session, service_account_id=a['account'], human_id=human, permissions=['decision:execute'],
                      scope=scope, expires_at=now()+timedelta(days=1))


@pytest.mark.parametrize('database', ['initial'], indirect=True)
def test_upgrade_backfills_valid_history(database):
    engine, sessions = database
    a, _ = graphs(sessions)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO test_runs (id,suite_id,revision_id,report,created_at) VALUES (:id,:suite,:revision,'{}',now())"),
                           {'id':str(uuid4()),'suite':a['suite'],'revision':a['revision']})
        connection.execute(text("INSERT INTO simulation_jobs (id,project_id,baseline_id,candidate_id,status,created_at) VALUES (:id,:project,:baseline,:candidate,'queued',now())"),
                           {'id':str(uuid4()),'project':a['project'],'baseline':a['revision'],'candidate':a['second']})
        connection.execute(insert(DecisionEvent).values(**event(a)))
    migrate(engine)
    migrate(engine)
    with engine.connect() as connection:
        assert connection.execute(text('SELECT policy_id FROM test_runs')).scalar_one() == a['policy']
        assert connection.execute(text('SELECT policy_id FROM simulation_jobs')).scalar_one() == a['policy']


@pytest.mark.parametrize('database', ['initial'], indirect=True)
def test_upgrade_rejects_existing_cross_tenant_links_and_rolls_back(database):
    engine, sessions = database
    a, b = graphs(sessions)
    with engine.begin() as connection:
        connection.execute(insert(DecisionEvent).values(**{**event(a), 'workspace_id':b['workspace']}))
    with pytest.raises(IntegrityError):
        migrate(engine)
    with engine.connect() as connection:
        assert connection.execute(text('SELECT count(*) FROM rulease_migrations')).scalar_one() == 1
        assert 'policy_id' not in {c['name'] for c in inspect(connection).get_columns('test_runs')}
