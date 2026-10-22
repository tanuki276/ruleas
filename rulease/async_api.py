"""Workspace-scoped control plane for asynchronous evaluation and rollouts."""
from typing import Literal
from fastapi import Depends, Header, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, func
from .models import Project, Policy, Revision, Environment, Deployment, SimulationJob, Job, Membership
from .async_models import Rollout, SimulationResult, ShadowResult
from .service import Conflict, digest
from .worker import enqueue, unseal
from . import rollouts


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class ReplayCase(Input):
    rule: str = Field(min_length=1, max_length=256)
    context: dict


class ReplayInput(Input):
    baseline: int = Field(gt=0)
    candidate: int = Field(gt=0)
    inputs: list[ReplayCase] = Field(min_length=1, max_length=1000)


class RolloutInput(Input):
    mode: Literal['shadow', 'canary']
    basis_points: int = Field(default=500, ge=0, le=10000)
    stickiness_path: str = Field(default='user.id', max_length=256)


class RolloutChange(Input):
    action: Literal['advance', 'pause', 'resume', 'rollback', 'promote', 'stop']
    basis_points: int | None = Field(default=None, ge=0, le=10000)


def register(app, service, settings, etag, size):
    @app.get('/v2/projects')
    def projects(svc=Depends(service)):
        svc.require('policy:read')
        return {'items': [dict(key=p.key, name=p.name) for p in svc.session.scalars(
            select(Project).where(Project.workspace_id == svc.workspace_id).order_by(Project.key))],
            'permissions': svc.session.scalar(select(Membership).where(Membership.workspace_id == svc.workspace_id,
                Membership.human_id == svc.human_id)).permissions}

    @app.get('/v2/projects/{project}/environments')
    def environments(project: str, svc=Depends(service)):
        svc.require('policy:read')
        p = svc.project(project)
        return {'items': [dict(key=e.key, version=e.version, required_approvals=e.required_approvals)
            for e in svc.session.scalars(select(Environment).where(Environment.project_id == p.id).order_by(Environment.key))]}

    @app.get('/v2/projects/{project}/policies/{policy}/revisions')
    def revisions(project: str, policy: str, before: int | None = None, svc=Depends(service)):
        svc.require('policy:read')
        p = svc.policy(svc.project(project), policy)
        query = select(Revision).where(Revision.policy_id == p.id)
        if before is not None:
            query = query.where(Revision.number < before)
        rows = svc.session.scalars(query.order_by(Revision.number.desc()).limit(51)).all()
        return {'items': [dict(revision=r.number, revision_hash=r.revision_hash, created_at=r.created_at) for r in rows[:50]],
            'next_cursor': rows[49].number if len(rows) > 50 else None}

    @app.get('/v2/projects/{project}/deployments')
    def deployments(project: str, cursor: str | None = None, svc=Depends(service)):
        svc.require('policy:read')
        query = select(Deployment).where(Deployment.project_id == svc.project(project).id)
        if cursor:
            query = query.where(Deployment.id > cursor)
        rows = svc.session.scalars(query.order_by(Deployment.id).limit(51)).all()
        return {'items': [dict(deployment_id=d.id, status=d.status, created_at=d.created_at,
            environment=svc.session.get(Environment, d.environment_id).key) for d in rows[:50]],
            'next_cursor': rows[49].id if len(rows)>50 else None}

    @app.post('/v2/projects/{project}/policies/{policy}/simulations', status_code=202)
    def replay(project: str, policy: str, body: ReplayInput,
               idempotency_key: str = Header(min_length=1, max_length=128), svc=Depends(service)):
        svc.require('revision:create')
        p = svc.policy(svc.project(project), policy)
        for item in body.inputs:
            size(item.context, settings.max_context_bytes)
        request_hash = digest(body.model_dump())
        dedup = digest([svc.workspace_id, p.id, 'replay', idempotency_key])
        # Serialize only the same submission key, not all work in a tenant.
        from sqlalchemy import text
        svc.session.execute(text('SELECT pg_advisory_xact_lock(:key)'), {'key': int(dedup[:15], 16)})
        existing = svc.session.scalar(select(Job).where(Job.dedup_key == dedup))
        if existing:
            simulation = svc.session.get(SimulationJob, existing.simulation_id)
            if simulation.request_hash != request_hash:
                raise Conflict('Idempotency key was used with another request')
            return {'simulation_id': simulation.id, 'status': simulation.status}
        ids = []
        for number in (body.baseline, body.candidate):
            r = svc.session.scalar(select(Revision).where(Revision.policy_id == p.id, Revision.number == number))
            if r is None:
                raise LookupError('Revision not found')
            ids.append(r.id)
        simulation = SimulationJob(project_id=p.project_id, policy_id=p.id, baseline_id=ids[0], candidate_id=ids[1], request_hash=request_hash)
        svc.session.add(simulation)
        svc.session.flush()
        enqueue(svc.session, settings, project_id=p.project_id, kind='replay', simulation_id=simulation.id,
            dedup_key=dedup, data={'inputs': [i.model_dump() for i in body.inputs]})
        return {'simulation_id': simulation.id, 'status': simulation.status}

    def simulation_for(svc, simulation_id):
        svc.require('policy:read')
        row = svc.session.scalar(select(SimulationJob).join(Project).where(SimulationJob.id == simulation_id,
            Project.workspace_id == svc.workspace_id))
        if row is None:
            raise LookupError('Simulation not found')
        return row

    @app.get('/v2/simulations/{simulation_id}')
    def simulation(simulation_id: str, svc=Depends(service)):
        row = simulation_for(svc, simulation_id)
        return dict(simulation_id=row.id, status=row.status, report=row.report)

    @app.get('/v2/simulations/{simulation_id}/results')
    def results(simulation_id: str, after: int = -1, changed_only: bool = True,
                old_result: str | None = None, new_result: str | None = None, svc=Depends(service)):
        row = simulation_for(svc, simulation_id)
        svc.require('decision:read')
        query = select(SimulationResult).where(SimulationResult.simulation_id == row.id, SimulationResult.position > after)
        from .models import now
        query = query.where(SimulationResult.expires_at > now())
        if changed_only:
            query = query.where(SimulationResult.changed == 1)
        if old_result:
            query = query.where(SimulationResult.old_result == old_result)
        if new_result:
            query = query.where(SimulationResult.new_result == new_result)
        rows = svc.session.scalars(query.order_by(SimulationResult.position).limit(51)).all()
        items = []
        for r in rows[:50]:
            envelope = unseal(settings, r.encrypted_context)
            if envelope['project_id'] != row.project_id or envelope['simulation_id'] != row.id:
                raise ValueError('Result envelope mismatch')
            items.append(dict(position=r.position, rule=r.rule, context=envelope['context'],
                old_result=r.old_result, new_result=r.new_result, changed=bool(r.changed)))
        return {'items': items, 'next_cursor': rows[49].position if len(rows) > 50 else None}

    @app.post('/v2/deployments/{deployment_id}/rollout', status_code=201)
    def start_rollout(deployment_id: str, body: RolloutInput, response: Response, svc=Depends(service)):
        result = rollouts.start(svc, deployment_id, **body.model_dump())
        response.headers['ETag'] = '"rollout-1"'
        return result

    @app.get('/v2/deployments/{deployment_id}/rollout')
    def get_rollout(deployment_id: str, response: Response, svc=Depends(service)):
        result = rollouts.describe(svc, deployment_id)
        response.headers['ETag'] = f'"rollout-{result["version"]}"'
        ids = select(Rollout.id).where(Rollout.deployment_id == deployment_id)
        count, changed = svc.session.execute(select(func.count(), func.coalesce(func.sum(ShadowResult.changed), 0))
            .where(ShadowResult.rollout_id.in_(ids))).one()
        result['shadow'] = dict(evaluated=count, changed=changed, agreement_percent=100*(count-changed)/count if count else None)
        return result

    @app.patch('/v2/deployments/{deployment_id}/rollout')
    def change_rollout(deployment_id: str, body: RolloutChange, response: Response,
                       if_match: str | None = Header(default=None), svc=Depends(service)):
        result = rollouts.change(svc, deployment_id, etag(if_match, 'rollout'), **body.model_dump())
        response.headers['ETag'] = f'"rollout-{result["version"]}"'
        return result

    @app.get('/v2/jobs')
    def jobs(cursor: str | None = None, svc=Depends(service)):
        svc.require('audit:read')
        query = select(Job).join(Project).where(Project.workspace_id == svc.workspace_id)
        if cursor:
            query = query.where(Job.id > cursor)
        rows = svc.session.scalars(query.order_by(Job.id).limit(51)).all()
        return {'items': [dict(job_id=r.id, kind=r.kind, state=r.state, attempts=r.attempts,
            last_error=r.last_error, available_at=r.available_at) for r in rows[:50]],
            'next_cursor': rows[49].id if len(rows)>50 else None}
