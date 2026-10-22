"""Transactional v2 operations. Caller owns commit/rollback; preview never writes."""
import hashlib
import json
import re
import time
from functools import lru_cache
from uuid import uuid4

from sqlalchemy import func, select
from rulea import ENGINE_VERSION, RuleEngine
from rulea.quality import lint, validate_context
from .models import (ApprovalRequest, DecisionEvent, Deployment, DeploymentItem,
                     Draft, Environment, Membership, Policy, Project, Release, Revision, now)


class Conflict(ValueError):
    pass


class Forbidden(ValueError):
    pass


PERMISSIONS = frozenset({'decision:execute', 'decision:read', 'policy:read', 'policy:write',
    'revision:create', 'deployment:create', 'deployment:approve', 'deployment:release', 'audit:read', 'admin:users'})
ROLE_PERMISSIONS = {
    'owner': PERMISSIONS, 'admin': PERMISSIONS,
    'editor': frozenset({'policy:read', 'policy:write', 'revision:create'}),
    'reviewer': frozenset({'policy:read', 'deployment:approve'}),
    'deployer': frozenset({'policy:read', 'deployment:create', 'deployment:release'}),
    'viewer': frozenset({'policy:read', 'decision:read'}),
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def valid_key(key):
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,127}', key):
        raise ValueError('Invalid stable key')
    return key


@lru_cache(maxsize=256)
def _compile(revision_hash, source, schema_json):
    if digest(dict(source=source, context_schema=json.loads(schema_json), engine_version=ENGINE_VERSION)) != revision_hash:
        raise ValueError('Revision hash or engine version mismatch')
    return RuleEngine.from_string(source)


def preview(source, rule, context, *, schema=None, trace='full'):
    if trace not in ('none', 'summary', 'full'):
        raise ValueError('Invalid trace mode')
    if schema is not None:
        errors = validate_context(schema, context)
        if errors:
            raise ValueError('Context validation failed: ' + json.dumps(errors))
    return trace_mode(RuleEngine.from_string(source).decide(rule, context).to_dict(), trace)


def trace_mode(result, mode):
    if mode == 'none':
        result['trace'], result['decisions'] = [], []
    elif mode == 'summary':
        result['trace'] = []
        result['decisions'] = [dict(rule=c['rule'], result=c['result'], reason=c['reason']) for c in result['decisions']]
    return result


class PolicyService:
    def __init__(self, session, workspace_id, human_id):
        self.session, self.workspace_id, self.human_id = session, workspace_id, human_id

    def require(self, permission):
        membership = self.session.scalar(select(Membership).where(
            Membership.workspace_id == self.workspace_id, Membership.human_id == self.human_id))
        if membership is None or permission not in membership.permissions:
            raise Forbidden('Permission required: ' + permission)

    def project(self, key):
        project = self.session.scalar(select(Project).where(Project.workspace_id == self.workspace_id, Project.key == key))
        if project is None:
            raise LookupError('Project not found')
        return project

    def policy(self, project, key, *, lock=False):
        query = select(Policy).where(Policy.project_id == project.id, Policy.key == key)
        policy = self.session.scalar(query.with_for_update() if lock else query)
        if policy is None:
            raise LookupError('Policy not found')
        return policy

    def environment(self, project, key, *, lock=False):
        query = select(Environment).where(Environment.project_id == project.id, Environment.key == key)
        env = self.session.scalar(query.with_for_update() if lock else query)
        if env is None:
            raise LookupError('Environment not found')
        return env

    def create_policy(self, project_key, key, name, source, schema=None):
        self.require('policy:write')
        project = self.project(project_key)
        policy = Policy(project_id=project.id, key=valid_key(key), name=name)
        self.session.add(policy)
        self.session.flush()
        draft = Draft(policy_id=policy.id, source=source, context_schema=schema or {})
        self.session.add(draft)
        self.session.flush()
        return policy, draft

    def save_draft(self, project_key, policy_key, source, schema, expected_version):
        self.require('policy:write')
        policy = self.policy(self.project(project_key), policy_key, lock=True)
        if policy.archived:
            raise Conflict('Policy is archived')
        draft = self.session.scalar(select(Draft).where(Draft.policy_id == policy.id).with_for_update())
        if draft.version != expected_version:
            raise Conflict('Draft ETag does not match')
        # Drafts may be invalid while editing. Validation happens on preview/commit.
        draft.source, draft.context_schema = source, schema
        draft.version += 1
        draft.updated_at = now()
        self.session.flush()
        return draft

    def commit(self, project_key, policy_key, expected_version):
        self.require('revision:create')
        policy = self.policy(self.project(project_key), policy_key, lock=True)
        if policy.archived:
            raise Conflict('Policy is archived')
        draft = self.session.scalar(select(Draft).where(Draft.policy_id == policy.id).with_for_update())
        if draft.version != expected_version:
            raise Conflict('Draft ETag does not match')
        diagnostics = lint(draft.source)
        if any(d.severity == 'ERROR' for d in diagnostics):
            raise ValueError('Policy has lint errors')
        # Validate schema even when there are no test contexts yet.
        validate_context(draft.context_schema, {})
        number = 1 + (self.session.scalar(select(func.max(Revision.number)).where(Revision.policy_id == policy.id)) or 0)
        revision = Revision(policy_id=policy.id, number=number, source=draft.source,
            context_schema=draft.context_schema, engine_version=ENGINE_VERSION, created_by=self.human_id,
            revision_hash=digest(dict(source=draft.source, context_schema=draft.context_schema, engine_version=ENGINE_VERSION)))
        self.session.add(revision)
        self.session.flush()
        return revision

    def create_deployment(self, project_key, environment, items, expected_version, *, activate_at=None):
        self.require('deployment:create')
        project = self.project(project_key)
        env = self.environment(project, environment, lock=True)
        if expected_version != env.version:
            raise Conflict('Environment ETag does not match')
        if not items:
            raise ValueError('Deployment requires at least one policy')
        if activate_at is not None and activate_at.utcoffset() is None:
            raise ValueError('activate_at requires an explicit timezone')
        deployment = Deployment(project_id=project.id, environment_id=env.id, created_by=self.human_id,
                                base_version=env.version, activate_at=activate_at)
        self.session.add(deployment)
        self.session.flush()
        for key, number in items.items():
            policy = self.policy(project, key)
            if policy.archived:
                raise Conflict('Policy is archived')
            revision = self.session.scalar(select(Revision).where(Revision.policy_id == policy.id, Revision.number == number))
            if revision is None:
                raise LookupError('Revision not found')
            self.session.add(DeploymentItem(deployment_id=deployment.id, project_id=project.id,
                                            policy_id=policy.id, revision_id=revision.id))
        self.session.flush()
        return deployment

    def deployment(self, deployment_id):
        deployment = self.session.scalar(select(Deployment).join(Project, Project.id == Deployment.project_id).where(
            Deployment.id == deployment_id, Project.workspace_id == self.workspace_id).with_for_update(of=Deployment))
        if deployment is None:
            raise LookupError('Deployment not found')
        return deployment

    def approve(self, deployment_id):
        self.require('deployment:approve')
        deployment = self.deployment(deployment_id)
        if deployment.status != 'pending':
            raise Conflict('Deployment is not pending')
        if deployment.created_by == self.human_id:
            raise Forbidden('Creator cannot approve own deployment')
        if self.session.scalar(select(ApprovalRequest).where(ApprovalRequest.deployment_id == deployment.id,
                ApprovalRequest.reviewer_id == self.human_id)):
            raise Conflict('Reviewer already voted')
        self.session.add(ApprovalRequest(deployment_id=deployment.id, reviewer_id=self.human_id, approved=True))
        self.session.flush()

    def release(self, deployment_id):
        self.require('deployment:release')
        deployment = self.deployment(deployment_id)
        env = self.session.scalar(select(Environment).where(Environment.id == deployment.environment_id).with_for_update())
        if deployment.status != 'pending' or env.version != deployment.base_version:
            raise Conflict('Deployment is stale or no longer pending')
        if deployment.activate_at and deployment.activate_at > now():
            raise Conflict('Scheduled release is not due')
        approvals = self.session.scalars(select(ApprovalRequest).where(ApprovalRequest.deployment_id == deployment.id)).all()
        if any(not a.approved for a in approvals) or len(approvals) < env.required_approvals:
            raise Conflict('Required approvals have not been met')
        items = self.session.scalars(select(DeploymentItem).where(DeploymentItem.deployment_id == deployment.id)).all()
        if not items:
            raise Conflict('Deployment is empty')
        env.version += 1
        deployment.status, deployment.released_at = 'released', now()
        self.session.flush()
        releases = []
        for item in items:
            policy = self.session.get(Policy, item.policy_id)
            if policy.archived:
                raise Conflict('Policy is archived')
            revision = self.session.get(Revision, item.revision_id)
            if any(d.severity == 'ERROR' for d in lint(revision.source)):
                raise Conflict('Revision has lint errors')
            release = Release(environment_id=env.id, deployment_id=deployment.id, policy_id=item.policy_id,
                              revision_id=item.revision_id, generation=env.version)
            self.session.add(release)
            releases.append(release)
        self.session.flush()
        return releases

    def rollback(self, project_key, environment, items, expected_version):
        # Same approval path as any other release; never copies source or creates a revision.
        return self.create_deployment(project_key, environment, items, expected_version)


def decide(session, *, workspace_id, service_account_id, project_key, policy_key, environment,
           rule, context, trace='none', settings=None):
    if trace not in ('none', 'summary', 'full'):
        raise ValueError('Invalid trace mode')
    project = session.scalar(select(Project).where(Project.workspace_id == workspace_id, Project.key == project_key))
    if project is None:
        raise LookupError('Project not found')
    policy = session.scalar(select(Policy).where(Policy.project_id == project.id, Policy.key == policy_key, Policy.archived.is_(False)))
    env = session.scalar(select(Environment).where(Environment.project_id == project.id, Environment.key == environment))
    if policy is None or env is None:
        raise LookupError('Policy or environment not found')
    release = session.scalar(select(Release).where(Release.environment_id == env.id, Release.policy_id == policy.id)
                             .order_by(Release.generation.desc()).limit(1))
    if release is None:
        raise LookupError('Policy has not been released')
    from .rollouts import current_rollout, route
    rollout = current_rollout(session, env.id, policy.id, release)
    release = route(session, release, rollout, context)
    revision = session.get(Revision, release.revision_id)
    errors = validate_context(revision.context_schema, context)
    if errors:
        raise ValueError('Context validation failed: ' + json.dumps(errors))
    started, evaluated_at = time.perf_counter_ns(), now()
    engine = _compile(revision.revision_hash, revision.source, json.dumps(revision.context_schema, sort_keys=True))
    result = trace_mode(engine.decide(rule, context).to_dict(), trace)
    duration = (time.perf_counter_ns() - started) // 1000
    decision_id = 'dec_' + uuid4().hex
    session.add(DecisionEvent(id=decision_id, created_at=evaluated_at, evaluated_at=evaluated_at,
        workspace_id=workspace_id, project_id=project.id, policy_id=policy.id, revision_id=revision.id,
        release_id=release.id, service_account_id=service_account_id, rule=rule,
        result=result['result'], reason=result['reason'], input_hash=digest(context), duration_us=duration))
    if settings is not None and rollout and rollout.mode == 'shadow' and rollout.state == 'active':
        from .worker import enqueue
        enqueue(session, settings, project_id=project.id, kind='shadow', rollout_id=rollout.id,
            dedup_key=decision_id, data=dict(candidate_id=rollout.candidate_revision_id, rule=rule, context=context,
                decision_id=decision_id, primary_result=result['result']))
    return dict(result, decision_id=decision_id, policy=policy_key, environment=environment,
                revision=revision.number, revision_hash=revision.revision_hash,
                release_id=release.id, duration_us=duration, evaluated_at=evaluated_at.isoformat())
