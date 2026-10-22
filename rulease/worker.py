"""Leased PostgreSQL queue. Evaluation runs outside the claim transaction."""
import base64
import hashlib
import json
import logging
import time
from collections import Counter
from datetime import timedelta
from uuid import uuid4

from cryptography.fernet import Fernet
from sqlalchemy import and_, or_, select, delete
from .models import Job, SimulationJob, Revision, LoginBucket, now
from .async_models import SimulationResult, ShadowResult, Rollout
from .service import digest, preview

logger = logging.getLogger(__name__)
MAX_ATTEMPTS = 5


class LeaseLost(Exception):
    pass


def cipher(settings):
    material = ('rulease-job-v1:' + settings.secret_key.get_secret_value()).encode()
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(material).digest()))


def seal(settings, value):
    return cipher(settings).encrypt(json.dumps(value, allow_nan=False).encode()).decode()


def unseal(settings, value):
    return json.loads(cipher(settings).decrypt(value.encode()))


def enqueue(session, settings, *, project_id, kind, data, simulation_id=None, rollout_id=None, dedup_key=None):
    if kind not in ('replay', 'shadow'):
        raise ValueError('Unsupported job kind')
    job = Job(id=str(uuid4()), project_id=project_id, kind=kind, simulation_id=simulation_id,
              rollout_id=rollout_id, dedup_key=dedup_key, payload={})
    job.payload = {'ciphertext': seal(settings, dict(job_id=job.id, project_id=project_id, data=data))}
    session.add(job)
    return job


def claim(sessions, settings):
    with sessions.begin() as session:
        current = now()
        job = session.scalar(select(Job).where(Job.kind.in_(['replay', 'shadow']),
            or_(and_(Job.state == 'queued', Job.available_at <= current),
                and_(Job.state == 'running', Job.locked_until <= current)))
            .order_by(Job.available_at, Job.id).with_for_update(skip_locked=True).limit(1))
        if job is None:
            return None
        if job.attempts >= MAX_ATTEMPTS:
            job.state, job.payload, job.last_error = 'failed', {}, 'Retry limit reached'
            job.locked_until, job.lock_token = None, None
            if job.simulation_id:
                session.get(SimulationJob, job.simulation_id).status = 'failed'
            return job
        job.state, job.lock_token = 'running', str(uuid4())
        job.attempts += 1
        job.locked_until = current + timedelta(seconds=settings.worker_lease_seconds)
        if job.simulation_id:
            session.get(SimulationJob, job.simulation_id).status = 'running'
        return job


def owned(session, job):
    row = session.scalar(select(Job).where(Job.id == job.id).with_for_update())
    if row is None or row.state != 'running' or row.lock_token != job.lock_token or row.locked_until <= now():
        raise LeaseLost()
    return row


def heartbeat(sessions, settings, job):
    with sessions.begin() as session:
        row = owned(session, job)
        row.locked_until = now() + timedelta(seconds=settings.worker_lease_seconds)


def evaluate(revision, rule, context):
    try:
        result = preview(revision.source, rule, context, schema=revision.context_schema, trace='none')
        return {'result': result['result'], 'reason': result['reason']}
    except Exception:
        # Contexts and exception text may contain personal data; persist a stable code only.
        return {'result': 'ERROR', 'reason': 'evaluation_failed'}


def compute(sessions, settings, job):
    envelope = unseal(settings, job.payload['ciphertext'])
    if envelope['job_id'] != job.id or envelope['project_id'] != job.project_id:
        raise ValueError('Job envelope mismatch')
    data = envelope['data']
    with sessions() as session:
        if job.kind == 'replay':
            simulation = session.get(SimulationJob, job.simulation_id)
            if simulation.project_id != job.project_id:
                raise ValueError('Simulation tenant mismatch')
            baseline = session.get(Revision, simulation.baseline_id)
            candidate = session.get(Revision, simulation.candidate_id)
        else:
            rollout = session.get(Rollout, job.rollout_id)
            if rollout.project_id != job.project_id:
                raise ValueError('Shadow tenant mismatch')
            # Pin the revision at enqueue time; changing a rollout cannot alter queued work.
            candidate = session.get(Revision, data['candidate_id'])
            if candidate.policy_id != rollout.policy_id:
                raise ValueError('Shadow revision mismatch')
    if job.kind == 'shadow':
        result = evaluate(candidate, data['rule'], data['context'])
        return dict(decision_id=data['decision_id'], input_hash=digest(data['context']),
                    primary_result=data['primary_result'], shadow_result=result['result'],
                    changed=int(data['primary_result'] != result['result']))
    results, transitions = [], Counter()
    last_heartbeat = time.monotonic()
    for position, item in enumerate(data['inputs']):
        if time.monotonic() - last_heartbeat >= settings.worker_lease_seconds / 3:
            heartbeat(sessions, settings, job)
            last_heartbeat = time.monotonic()
        before, after = evaluate(baseline, item['rule'], item['context']), evaluate(candidate, item['rule'], item['context'])
        changed = int(before != after)
        transitions[before['result'] + ' → ' + after['result']] += 1
        results.append(dict(position=position, rule=item['rule'], input_hash=digest(item['context']),
            old_result=before['result'], new_result=after['result'], changed=changed,
            encrypted_context=seal(settings, dict(project_id=job.project_id, simulation_id=job.simulation_id, context=item['context']))))
    changed = sum(r['changed'] for r in results)
    return dict(results=results, report=dict(evaluated=len(results), changed=changed,
        unchanged=len(results)-changed, change_percent=100*changed/len(results), transitions=dict(transitions)))


def finish(sessions, settings, job, output):
    with sessions.begin() as session:
        row = owned(session, job)
        if job.kind == 'replay':
            for item in output['results']:
                session.add(SimulationResult(simulation_id=job.simulation_id, project_id=job.project_id,
                    expires_at=now()+timedelta(days=settings.retention_days), **item))
            simulation = session.get(SimulationJob, job.simulation_id)
            simulation.status, simulation.report = 'completed', output['report']
        else:
            session.add(ShadowResult(job_id=job.id, rollout_id=job.rollout_id, project_id=job.project_id, **output))
        row.state, row.payload, row.last_error = 'completed', {}, None
        row.lock_token, row.locked_until = None, None


def fail(sessions, job):
    with sessions.begin() as session:
        row = owned(session, job)
        row.last_error = 'Job execution failed'
        row.lock_token, row.locked_until = None, None
        if row.attempts >= MAX_ATTEMPTS:
            row.state, row.payload = 'failed', {}
            if row.simulation_id:
                session.get(SimulationJob, row.simulation_id).status = 'failed'
        else:
            row.state = 'queued'
            row.available_at = now() + timedelta(seconds=min(300, 2 ** row.attempts))


def run_once(sessions, settings):
    job = claim(sessions, settings)
    if job is None:
        return False
    if job.state == 'failed':
        return True
    try:
        finish(sessions, settings, job, compute(sessions, settings, job))
    except LeaseLost:
        pass  # A replacement worker owns the result; never overwrite it.
    except Exception:
        logger.warning('job_failed', extra={'job_id': job.id, 'job_kind': job.kind})
        try:
            fail(sessions, job)
        except LeaseLost:
            pass
    return True


def cleanup(sessions, settings):
    with sessions.begin() as session:
        expired = session.scalars(select(Job).where(Job.kind.in_(['replay', 'shadow']),
            Job.created_at < now()-timedelta(days=settings.retention_days),
            Job.state.in_(['queued', 'running']),
            or_(Job.locked_until.is_(None), Job.locked_until < now())).with_for_update(skip_locked=True).limit(100)).all()
        for job in expired:
            job.state, job.payload, job.last_error = 'failed', {}, 'Input retention expired'
            job.lock_token, job.locked_until = None, None
            if job.simulation_id:
                session.get(SimulationJob, job.simulation_id).status = 'failed'
        session.execute(delete(LoginBucket).where(LoginBucket.reset_at < now()))
        session.execute(delete(SimulationResult).where(SimulationResult.expires_at < now()))
        session.execute(delete(ShadowResult).where(ShadowResult.created_at < now()-timedelta(days=settings.retention_days)))


def run(sessions, settings, stop):
    next_cleanup = 0
    while not stop.is_set():
        if time.monotonic() >= next_cleanup:
            cleanup(sessions, settings)
            next_cleanup = time.monotonic() + 60
        if not run_once(sessions, settings):
            stop.wait(settings.worker_poll_seconds)
