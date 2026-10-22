"""Approved bundle canaries and asynchronous, non-authoritative shadows."""
import hashlib
import json
import re
from sqlalchemy import select
from .models import DeploymentItem, Environment, Policy, Release, Revision
from .async_models import Rollout
from .service import Conflict, digest


def bucket(deployment_id, value):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or value == '':
        raise ValueError('Stickiness value must be a non-empty string or integer')
    encoded = json.dumps([deployment_id, value], separators=(',', ':'), ensure_ascii=False).encode()
    return int.from_bytes(hashlib.sha256(encoded).digest()[:8], 'big') % 10000


def sticky_value(context, path):
    value = context
    for part in path.split('.'):
        if not isinstance(value, dict) or part not in value:
            raise ValueError('Canary stickiness field is missing')
        value = value[part]
    return value


def current_rollout(session, environment_id, policy_id, latest):
    rows = session.scalars(select(Rollout).where(Rollout.environment_id == environment_id,
        Rollout.policy_id == policy_id, Rollout.state != 'stopped').order_by(Rollout.created_at.desc(), Rollout.id.desc())).all()
    for row in rows:
        anchor = row.baseline_release_id if row.mode == 'shadow' else row.candidate_release_id
        if latest.id == anchor:
            return row
    return None


def route(session, latest, rollout, context):
    if rollout is None or rollout.mode == 'shadow':
        return latest
    if rollout.state == 'completed':
        return latest
    if rollout.state in ('paused', 'rolled_back'):
        return session.get(Release, rollout.baseline_release_id)
    value = sticky_value(context, rollout.stickiness_path)
    if bucket(rollout.deployment_id, value) < rollout.basis_points:
        return latest
    return session.get(Release, rollout.baseline_release_id)


def start(svc, deployment_id, mode, basis_points, stickiness_path):
    svc.require('deployment:release')
    if mode not in ('shadow', 'canary') or not 0 <= basis_points <= 10000:
        raise ValueError('Invalid rollout')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*', stickiness_path):
        raise ValueError('Invalid stickiness path')
    deployment = svc.deployment(deployment_id)
    env = svc.session.scalar(select(Environment).where(Environment.id == deployment.environment_id).with_for_update())
    if deployment.status != 'pending' or deployment.base_version != env.version:
        raise Conflict('Deployment is stale or no longer pending')
    if svc.session.scalar(select(Rollout).where(Rollout.deployment_id == deployment.id)):
        raise Conflict('Deployment already has a rollout')
    items = svc.session.scalars(select(DeploymentItem).where(DeploymentItem.deployment_id == deployment.id)).all()
    if not items:
        raise Conflict('Deployment is empty')
    baselines = {}
    for item in items:
        latest = svc.session.scalar(select(Release).where(Release.environment_id == env.id,
            Release.policy_id == item.policy_id).order_by(Release.generation.desc()).limit(1))
        if latest is None:
            raise Conflict('Rollout requires an existing release for every policy')
        previous = current_rollout(svc.session, env.id, item.policy_id, latest)
        if previous and previous.state in ('active', 'paused'):
            raise Conflict('Stop or finish the existing rollout first')
        baselines[item.policy_id] = route(svc.session, latest, previous, {}).id
    # release() enforces environment approvals, lint, schedule and bundle atomicity.
    releases = {r.policy_id: r.id for r in svc.release(deployment.id)} if mode == 'canary' else {}
    for item in items:
        svc.session.add(Rollout(project_id=deployment.project_id, environment_id=env.id,
            policy_id=item.policy_id, deployment_id=deployment.id, baseline_release_id=baselines[item.policy_id],
            candidate_revision_id=item.revision_id, candidate_release_id=releases.get(item.policy_id),
            mode=mode, basis_points=basis_points if mode == 'canary' else 0,
            stickiness_path=stickiness_path, state='completed' if mode == 'canary' and basis_points == 10000 else 'active'))
    svc.session.flush()
    return describe(svc, deployment_id)


def describe(svc, deployment_id):
    svc.require('policy:read')
    # Tenant filter precedes exposing either rollout identifiers or configuration.
    deployment = svc.deployment(deployment_id)
    rows = svc.session.scalars(select(Rollout).where(Rollout.deployment_id == deployment.id).order_by(Rollout.policy_id)).all()
    if not rows:
        raise LookupError('Rollout not found')
    return {'deployment_id': deployment.id, 'mode': rows[0].mode, 'state': rows[0].state,
        'version': rows[0].version, 'basis_points': rows[0].basis_points, 'stickiness_path': rows[0].stickiness_path,
        'policies': [{'policy': svc.session.get(Policy, r.policy_id).key,
                      'candidate_revision': svc.session.get(Revision, r.candidate_revision_id).number} for r in rows]}


def change(svc, deployment_id, expected_version, action, basis_points=None):
    svc.require('deployment:release')
    deployment = svc.deployment(deployment_id)
    svc.session.scalar(select(Environment).where(Environment.id == deployment.environment_id).with_for_update())
    rows = svc.session.scalars(select(Rollout).where(Rollout.deployment_id == deployment.id).with_for_update()).all()
    if not rows:
        raise LookupError('Rollout not found')
    for row in rows:
        if row.version != expected_version:
            raise Conflict('Rollout ETag does not match')
        latest = svc.session.scalar(select(Release).where(Release.environment_id == row.environment_id,
            Release.policy_id == row.policy_id).order_by(Release.generation.desc()).limit(1))
        current = current_rollout(svc.session, row.environment_id, row.policy_id, latest)
        if current is None or current.id != row.id:
            raise Conflict('Rollout has been superseded')
        if row.state not in ('active', 'paused'):
            raise Conflict('Rollout is terminal')
        if row.mode == 'shadow':
            if action != 'stop':
                raise ValueError('Shadow supports stop only')
            row.state = 'stopped'
        elif action == 'pause' and row.state == 'active':
            row.state = 'paused'
        elif action == 'resume' and row.state == 'paused':
            row.state = 'active'
        elif action == 'rollback':
            row.state = 'rolled_back'
        elif action in ('advance', 'promote') and row.state == 'active':
            target = 10000 if action == 'promote' else basis_points
            if target is None or not row.basis_points < target <= 10000:
                raise ValueError('Canary percentage must increase, up to 100%')
            row.basis_points = target
            if target == 10000:
                row.state = 'completed'
        else:
            raise ValueError('Invalid rollout transition')
        row.version += 1
    svc.session.flush()
    return describe(svc, deployment_id)
