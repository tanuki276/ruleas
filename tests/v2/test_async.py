from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError
from fastapi.testclient import TestClient
from rulease.models import Job, SimulationJob, Environment, ServiceAccount, Release, DecisionEvent, now
from rulease.async_models import Rollout, SimulationResult, ShadowResult
from rulease.service import PolicyService, decide, Conflict
from rulease.rollouts import start, change, bucket
from rulease.worker import claim, compute, finish, run_once, enqueue, LeaseLost, seal, unseal
from rulease.config import Settings
from test_foundation import seed, SOURCE
from test_postgresql import database, URL
from test_auth_postgresql import app_for, credentials


def test_sticky_assignment_is_stable_and_monotone():
    values = [bucket('deployment', f'user-{i}') for i in range(10000)]
    assert values == [bucket('deployment', f'user-{i}') for i in range(10000)]
    small = {i for i,v in enumerate(values) if v < 500}
    large = {i for i,v in enumerate(values) if v < 2500}
    assert small < large
    assert 400 < len(small) < 600
    assert bucket('deployment', 12) != bucket('deployment', '12')
    with pytest.raises(ValueError):
        bucket('deployment', {})


def test_encrypted_payload_requires_correct_secret():
    settings = Settings(database_url='postgresql://localhost/db', secret_key='x'*32)
    token = seal(settings, {'context': {'email': 'private@example.com'}})
    assert 'private@example.com' not in token
    assert unseal(settings, token)['context']['email'] == 'private@example.com'
    other = Settings(database_url='postgresql://localhost/db', secret_key='y'*32)
    with pytest.raises(Exception):
        unseal(other, token)


def setup(sessions):
    with sessions.begin() as s:
        w,u,_ = seed(s)
        s.scalar(select(Environment)).required_approvals = 0
        svc = PolicyService(s,w.id,u.id)
        p,_ = svc.create_policy('commerce','checkout','Checkout',SOURCE)
        first = svc.commit('commerce','checkout',1)
        d = svc.create_deployment('commerce','production',{'checkout':1},1)
        release = svc.release(d.id)[0]
        svc.save_draft('commerce','checkout',SOURCE.replace('10000','8000'),{},1)
        second = svc.commit('commerce','checkout',2)
        candidate = svc.create_deployment('commerce','production',{'checkout':2},2)
        account = s.scalar(select(ServiceAccount))
        return dict(workspace=w.id, human=u.id, policy=p.id, project=p.project_id, first=first.id,
            second=second.id, deployment=candidate.id, account=account.id, release=release.id)


def args(c, amount=9000):
    return dict(workspace_id=c['workspace'], service_account_id=c['account'], project_key='commerce',
        policy_key='checkout', environment='production', rule='discount',context={'amount':amount,'user':{'id':'user-1'}})


def config():
    return Settings(database_url=URL,secret_key='x'*32)


def replay_job(sessions,c,settings):
    with sessions.begin() as s:
        sim=SimulationJob(project_id=c['project'],policy_id=c['policy'],baseline_id=c['first'],candidate_id=c['second'])
        s.add(sim);s.flush()
        job=enqueue(s,settings,project_id=c['project'],kind='replay',simulation_id=sim.id,
            data={'inputs':[{'rule':'discount','context':{'amount':9000}},{'rule':'discount','context':{'amount':11000}}]})
        s.flush()
        return job.id,sim.id


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_replay_claim_is_exclusive_and_completes_once(database):
    _,sessions=database;c=setup(sessions);settings=config();job_id,sim_id=replay_job(sessions,c,settings)
    with ThreadPoolExecutor(max_workers=6) as pool:
        claimed=list(pool.map(lambda _:claim(sessions,settings),range(6)))
    jobs=[j for j in claimed if j]
    assert len(jobs)==1
    output=compute(sessions,settings,jobs[0]);finish(sessions,settings,jobs[0],output)
    with pytest.raises(LeaseLost):finish(sessions,settings,jobs[0],output)
    with sessions() as s:
        sim=s.get(SimulationJob,sim_id)
        assert sim.report['evaluated']==2 and sim.report['changed']==1
        assert s.get(Job,job_id).payload=={}
        assert s.scalar(select(func.count()).select_from(SimulationResult))==2
        assert s.scalar(select(func.count()).select_from(DecisionEvent))==0


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_expired_lease_fences_old_worker_and_recovers(database):
    engine,sessions=database;c=setup(sessions);settings=config();job_id,_=replay_job(sessions,c,settings)
    old=claim(sessions,settings)
    with engine.begin() as con:con.execute(update(Job).where(Job.id==job_id).values(locked_until=now()-timedelta(seconds=1)))
    new=claim(sessions,settings)
    assert old.lock_token!=new.lock_token and new.attempts==2
    with pytest.raises(LeaseLost):finish(sessions,settings,old,compute(sessions,settings,old))
    finish(sessions,settings,new,compute(sessions,settings,new))


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_corrupt_payload_retries_then_dead_letters_without_plaintext(database):
    engine,sessions=database;c=setup(sessions);settings=config();job_id,sim_id=replay_job(sessions,c,settings)
    with engine.begin() as con:con.execute(update(Job).where(Job.id==job_id).values(payload={'ciphertext':'invalid'}))
    for _ in range(5):
        assert run_once(sessions,settings)
        with engine.begin() as con:con.execute(update(Job).where(Job.id==job_id).values(available_at=now()-timedelta(seconds=1)))
    with sessions() as s:
        assert s.get(Job,job_id).state=='failed'
        assert s.get(Job,job_id).payload=={}
        assert s.get(SimulationJob,sim_id).status=='failed'


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_shadow_never_changes_primary_and_worker_records_delta(database):
    _,sessions=database;c=setup(sessions);settings=config()
    with sessions.begin() as s:
        start(PolicyService(s,c['workspace'],c['human']),c['deployment'],'shadow',0,'user.id')
        r=decide(s,settings=settings,**args(c))
        assert r['result']=='DENY' and r['revision']==1
    assert run_once(sessions,settings)
    with sessions() as s:
        result=s.scalar(select(ShadowResult))
        assert (result.primary_result,result.shadow_result,result.changed)==('DENY','ALLOW',1)
        assert s.scalar(select(func.count()).select_from(DecisionEvent))==1
        assert s.scalar(select(func.count()).select_from(Release))==1


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_canary_pause_resume_rollback_and_stale_etag(database):
    _,sessions=database;c=setup(sessions)
    with sessions.begin() as s:
        svc=PolicyService(s,c['workspace'],c['human'])
        start(svc,c['deployment'],'canary',500,'user.id')
        expected=2 if bucket(c['deployment'],'user-1')<500 else 1
        assert decide(s,**args(c))['revision']==expected
        change(svc,c['deployment'],1,'pause')
        assert decide(s,**args(c))['revision']==1
        with pytest.raises(Conflict):change(svc,c['deployment'],1,'resume')
        change(svc,c['deployment'],2,'resume')
        change(svc,c['deployment'],3,'rollback')
        assert decide(s,**args(c))['revision']==1
        assert s.scalar(select(func.count()).select_from(Release))==2


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_canary_approval_and_promotion(database):
    _,sessions=database;c=setup(sessions)
    with sessions.begin() as s:s.scalar(select(Environment)).required_approvals=1
    with pytest.raises(Conflict),sessions.begin() as s:
        start(PolicyService(s,c['workspace'],c['human']),c['deployment'],'canary',500,'user.id')
    with sessions.begin() as s:
        s.scalar(select(Environment)).required_approvals=0
        svc=PolicyService(s,c['workspace'],c['human'])
        start(svc,c['deployment'],'canary',500,'user.id')
        change(svc,c['deployment'],1,'promote')
        assert decide(s,**args(c))['revision']==2


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_job_and_rollout_tenant_integrity(database):
    _,sessions=database;c=setup(sessions);settings=config()
    from rulease.models import Workspace,Project
    with sessions.begin() as s:
        w=Workspace(key='other',name='Other');s.add(w);s.flush()
        p=Project(workspace_id=w.id,key='other',name='Other');s.add(p);s.flush();other=p.id
    job_id,_=replay_job(sessions,c,settings)
    with pytest.raises(IntegrityError),sessions.begin() as s:
        job=s.get(Job,job_id);job.project_id=other;s.flush()
    with pytest.raises(IntegrityError),sessions.begin() as s:
        s.add(Rollout(project_id=other,environment_id=s.scalar(select(Environment)).id,policy_id=c['policy'],
            deployment_id=c['deployment'],baseline_release_id=c['release'],candidate_revision_id=c['second'],
            mode='shadow',stickiness_path='user.id'));s.flush()


@pytest.mark.skipif(not URL,reason='Requires PostgreSQL')
def test_replay_http_idempotency_results_and_tenant_boundary(database,monkeypatch):
    _,sessions=database;c=setup(sessions)
    from rulease.security import issue_session
    from rulease.models import Human, Workspace, Membership
    from rulease.service import ROLE_PERMISSIONS
    with sessions.begin() as s:
        token=issue_session(s,c['human'])
        w=Workspace(key='other',name='Other');u=Human(username='other');s.add_all([w,u]);s.flush()
        s.add(Membership(workspace_id=w.id,human_id=u.id,permissions=sorted(ROLE_PERMISSIONS['owner'])))
        other=issue_session(s,u.id)
    app=app_for(database,monkeypatch)
    headers={'Authorization':'Bearer '+token,'X-Rulease-Workspace':'team','Idempotency-Key':'same-request'}
    path='/v2/projects/commerce/policies/checkout/simulations'
    body={'baseline':1,'candidate':2,'inputs':[{'rule':'discount','context':{'amount':9000}}]}
    with TestClient(app) as client:
        response=client.post(path,headers=headers,json=body)
        assert response.status_code==202,response.text
        sim_id=response.json()['simulation_id']
        assert client.post(path,headers=headers,json=body).json()['simulation_id']==sim_id
        assert client.post(path,headers=headers,json={**body,'candidate':1}).status_code==412
        assert run_once(sessions,config())
        assert client.get('/v2/simulations/'+sim_id,headers=headers).json()['report']['changed']==1
        result=client.get('/v2/simulations/'+sim_id+'/results',headers=headers)
        assert result.status_code==200,result.text
        assert result.json()['items'][0]['context']=={'amount':9000}
        assert client.get('/v2/simulations/'+sim_id,headers={'Authorization':'Bearer '+other,'X-Rulease-Workspace':'other'}).status_code==404
        assert client.get('/v2/jobs',headers=headers).json()['items'][0]['state']=='completed'


def test_spa_is_packaged_with_scoped_content_security_policy():
    from pathlib import Path
    from rulease.server import create_app
    if not (Path(__file__).parents[2]/'rulease/static/index.html').exists():
        pytest.skip('Frontend is built in the distributions/frontend CI jobs')
    app=create_app(Settings(database_url='postgresql://localhost/db',secret_key='x'*32))
    try:
        with TestClient(app) as client:
            response=client.get('/admin/')
            assert response.status_code==200
            assert 'script-src' in response.headers['content-security-policy']
            assert 'src="/admin/assets/' in response.text
            assert client.get('/health/live').headers['content-security-policy'].startswith("default-src 'none'")
    finally:
        app.state.engine.dispose()
