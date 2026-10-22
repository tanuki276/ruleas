"""Initial v2 HTTP contract for the draft/revision/release lifecycle."""
import base64
import json
import secrets
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert
from .config import Settings
from .database import connect
from .models import (APIKey, AuthSession, Draft, Environment, Human, LoginBucket,
                     Policy, Project, Release, Revision, ServiceAccount, TestSuite, TestCase, TestRun, Workspace, now)
from .security import (authenticate_human, authenticate_key, hash_password, issue_key,
                       issue_session, token_digest, verify_password)
from .service import Conflict, Forbidden, PolicyService, decide, preview


class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Login(Contract):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PolicyInput(Contract):
    key: str
    name: str = Field(min_length=1, max_length=256)
    source: str
    context_schema: dict = Field(default_factory=dict)


class DraftInput(Contract):
    source: str
    context_schema: dict = Field(default_factory=dict)


class PreviewInput(Contract):
    source: str
    rule: str
    context: dict
    context_schema: dict = Field(default_factory=dict)
    trace: str = 'full'


class PreviewContext(Contract):
    rule: str
    context: dict
    trace: str = 'full'


class SuiteInput(Contract):
    name: str = Field(min_length=1, max_length=256)
    cases: list[dict] = Field(min_length=1, max_length=1000)


class DecisionInput(Contract):
    project: str
    policy: str
    environment: str = 'production'
    rule: str
    context: dict
    trace: str = 'none'


class BatchInput(Contract):
    items: list[DecisionInput] = Field(min_length=1)


class DeploymentInput(Contract):
    environment: str
    items: dict[str, int]
    activate_at: datetime | None = None


class KeyInput(Contract):
    service_account: str = Field(min_length=1, max_length=128)
    permissions: list[str]
    scope: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime


def etag(value, kind):
    if value is None:
        raise HTTPException(428, 'If-Match is required')
    prefix = '"' + kind + '-'
    if not value.startswith(prefix) or not value.endswith('"') or not value[len(prefix):-1].isdigit():
        raise HTTPException(412, 'Invalid ETag')
    return int(value[len(prefix):-1])


def create_app(settings=None):
    settings = settings or Settings()
    engine, sessions = connect(settings.database_url)
    app = FastAPI(title='Rulease', version='2.0.0-alpha.1', description='Immutable policy revision and release API')
    app.state.engine, app.state.sessions = engine, sessions

    @app.middleware('http')
    async def security(request, call_next):
        request_id = uuid4().hex
        request.state.request_id = request_id
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > settings.max_body_bytes:
                return JSONResponse(dict(type='about:blank', title='Request too large', status=413, request_id=request_id),
                                    status_code=413, media_type='application/problem+json', headers={'X-Request-ID': request_id})
        request._body = bytes(data)
        response = await call_next(request)
        response.headers.update({'X-Request-ID': request_id, 'X-Content-Type-Options': 'nosniff',
            'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
            'Cache-Control': 'no-store'})
        if settings.production:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(dict(type='about:blank', title='Request validation failed', status=422,
            request_id=getattr(request.state, 'request_id', None)), status_code=422, media_type='application/problem+json')

    @app.exception_handler(IntegrityError)
    async def integrity_error(request, exc):
        return JSONResponse(dict(type='about:blank', title='Resource conflict', status=409,
            request_id=getattr(request.state, 'request_id', None)), status_code=409, media_type='application/problem+json')

    @app.exception_handler(Exception)
    async def unexpected(request, exc):
        return JSONResponse(dict(type='about:blank', title='Internal server error', status=500,
                                 request_id=getattr(request.state, 'request_id', None)),
                            status_code=500, media_type='application/problem+json')

    async def problem(request, exc):
        status = (412 if isinstance(exc, Conflict) else 403 if isinstance(exc, Forbidden) else
                  404 if isinstance(exc, LookupError) else exc.status_code if isinstance(exc, HTTPException) else 422)
        return JSONResponse(dict(type='about:blank', title=str(exc.detail if isinstance(exc, HTTPException) else exc),
                                 status=status, request_id=getattr(request.state, 'request_id', None)),
                            status_code=status, media_type='application/problem+json')
    for error in (Conflict, Forbidden, LookupError, ValueError, HTTPException):
        app.add_exception_handler(error, problem)

    def db():
        with sessions.begin() as session:
            yield session

    def bearer(authorization: str = Header(default='')):
        if not authorization.startswith('Bearer '):
            raise HTTPException(401, 'Bearer credential required')
        return authorization[7:]

    def workspace(x_rulease_workspace: str = Header(), session=Depends(db)):
        found = session.scalar(select(Workspace).where(Workspace.key == x_rulease_workspace))
        if found is None:
            raise HTTPException(404, 'Workspace not found')
        return found

    def human(token=Depends(bearer), session=Depends(db)):
        return authenticate_human(session, token)

    def service(workspace=Depends(workspace), human=Depends(human), session=Depends(db)):
        return PolicyService(session, workspace.id, human.human_id)

    def size(value, maximum):
        if len(json.dumps(value, allow_nan=False).encode()) > maximum:
            raise HTTPException(413, 'Resource exceeds configured limit')

    def source_size(source):
        if len(source.encode()) > settings.max_source_bytes:
            raise HTTPException(413, 'Source exceeds configured limit')

    @app.get('/health/live')
    def live():
        return {'status': 'ok'}

    @app.get('/health/ready')
    def ready():
        try:
            with engine.connect() as connection:
                connection.execute(text('SELECT 1 FROM rulease_migrations LIMIT 1'))
            return {'status': 'ready'}
        except Exception:
            raise HTTPException(503, 'Database is unavailable or migration is missing')

    @app.post('/v2/auth/login')
    def login(body: Login):
        # Persist attempts independently of successful authentication transactions.
        with sessions.begin() as session:
            key = token_digest(body.username)
            stmt = insert(LoginBucket).values(key=key, count=1, reset_at=now() + timedelta(minutes=15))
            bucket = session.execute(stmt.on_conflict_do_update(index_elements=[LoginBucket.key],
                set_={'count': LoginBucket.count + 1}).returning(LoginBucket.count, LoginBucket.reset_at)).one()
            if bucket[1] < now():
                session.execute(LoginBucket.__table__.update().where(LoginBucket.key == key).values(
                    count=1, reset_at=now() + timedelta(minutes=15)))
                count = 1
            else:
                count = bucket[0]
        if count > 10:
            raise HTTPException(429, 'Too many login attempts')
        with sessions.begin() as session:
            user = session.scalar(select(Human).where(Human.username == body.username))
            # A fixed dummy hash avoids skipping the expensive verification on unknown users.
            encoded = user.password_hash if user and user.password_hash else app.state.dummy_hash
            valid, replacement = verify_password(body.password, encoded)
            if not valid or user is None:
                raise HTTPException(401, 'Invalid credentials')
            if replacement:
                user.password_hash = replacement
            token = issue_session(session, user.id)
        return {'session_token': token, 'token_type': 'Bearer', 'expires_in': 43200, 'idle_timeout': 1800}

    app.state.dummy_hash = hash_password(secrets.token_urlsafe(32))

    @app.post('/v2/auth/rotate')
    def rotate(human=Depends(human), session=Depends(db)):
        human.revoked_at = now()
        return {'session_token': issue_session(session, human.human_id, expires_at=human.expires_at), 'token_type': 'Bearer'}

    @app.post('/v2/auth/logout-all', status_code=204)
    def logout_all(human=Depends(human), session=Depends(db)):
        session.execute(AuthSession.__table__.update().where(AuthSession.human_id == human.human_id).values(revoked_at=now()))
        return Response(status_code=204)

    @app.get('/v2/projects/{project}/policies')
    def policies(project: str, limit: int = 50, cursor: str | None = None, svc=Depends(service)):
        svc.require('policy:read')
        if not 1 <= limit <= 200:
            raise ValueError('limit must be between 1 and 200')
        found = svc.project(project)
        query = select(Policy).where(Policy.project_id == found.id)
        if cursor:
            try:
                key = base64.urlsafe_b64decode(cursor.encode()).decode()
            except (ValueError, UnicodeError):
                raise ValueError('Invalid cursor')
            query = query.where(Policy.key > key)
        rows = svc.session.scalars(query.order_by(Policy.key).limit(limit + 1)).all()
        return {'items': [dict(key=p.key, name=p.name, archived=p.archived) for p in rows[:limit]],
                'next_cursor': base64.urlsafe_b64encode(rows[limit-1].key.encode()).decode() if len(rows) > limit else None}

    @app.post('/v2/projects/{project}/policies', status_code=201)
    def create_policy(project: str, body: PolicyInput, response: Response, svc=Depends(service)):
        source_size(body.source)
        policy, draft = svc.create_policy(project, body.key, body.name, body.source, body.context_schema)
        response.headers['ETag'] = '"draft-1"'
        return {'key': policy.key, 'name': policy.name, 'draft_version': draft.version}

    @app.get('/v2/projects/{project}/policies/{policy}/draft')
    def get_draft(project: str, policy: str, response: Response, svc=Depends(service)):
        svc.require('policy:read')
        p = svc.policy(svc.project(project), policy)
        draft = svc.session.scalar(select(Draft).where(Draft.policy_id == p.id))
        response.headers['ETag'] = f'"draft-{draft.version}"'
        return dict(source=draft.source, context_schema=draft.context_schema, version=draft.version)

    @app.put('/v2/projects/{project}/policies/{policy}/draft')
    def save(project: str, policy: str, body: DraftInput, response: Response,
             if_match: str | None = Header(default=None), svc=Depends(service)):
        source_size(body.source)
        draft = svc.save_draft(project, policy, body.source, body.context_schema, etag(if_match, 'draft'))
        response.headers['ETag'] = f'"draft-{draft.version}"'
        return {'version': draft.version}

    @app.post('/v2/projects/{project}/policies/{policy}/revisions', status_code=201)
    def commit(project: str, policy: str, if_match: str | None = Header(default=None), svc=Depends(service)):
        revision = svc.commit(project, policy, etag(if_match, 'draft'))
        return dict(revision=revision.number, revision_hash=revision.revision_hash)

    @app.get('/v2/projects/{project}/policies/{policy}/revisions/{number}')
    def revision(project: str, policy: str, number: int, svc=Depends(service)):
        svc.require('policy:read')
        p = svc.policy(svc.project(project), policy)
        r = svc.session.scalar(select(Revision).where(Revision.policy_id == p.id, Revision.number == number))
        if r is None:
            raise LookupError('Revision not found')
        return dict(revision=r.number, source=r.source, context_schema=r.context_schema, revision_hash=r.revision_hash)

    @app.post('/v2/preview')
    def preview_source(body: PreviewInput, svc=Depends(service)):
        svc.require('policy:read')
        source_size(body.source)
        size(body.context, settings.max_context_bytes)
        return preview(body.source, body.rule, body.context, schema=body.context_schema, trace=body.trace)

    @app.post('/v2/projects/{project}/policies/{policy}/draft/preview')
    def preview_draft(project: str, policy: str, body: PreviewContext, svc=Depends(service)):
        svc.require('policy:read')
        p = svc.policy(svc.project(project), policy)
        draft = svc.session.scalar(select(Draft).where(Draft.policy_id == p.id))
        size(body.context, settings.max_context_bytes)
        return preview(draft.source, body.rule, body.context, schema=draft.context_schema, trace=body.trace)

    @app.post('/v2/lint')
    def lint_source(body: DraftInput, svc=Depends(service)):
        from rulea.quality import lint, validate_context
        svc.require('policy:read')
        source_size(body.source)
        validate_context(body.context_schema, {})
        return {'diagnostics': [d.to_dict() for d in lint(body.source)]}

    def find_revision(svc, project, policy, number):
        svc.require('policy:read')
        p = svc.policy(svc.project(project), policy)
        revision = svc.session.scalar(select(Revision).where(Revision.policy_id == p.id, Revision.number == number))
        if revision is None:
            raise LookupError('Revision not found')
        return revision

    @app.post('/v2/projects/{project}/policies/{policy}/revisions/{number}/tests')
    def tests(project: str, policy: str, number: int, body: SuiteInput, svc=Depends(service)):
        from rulea.quality import run_suite
        svc.require('revision:create')
        revision = find_revision(svc, project, policy, number)
        for case in body.cases:
            size(case.get('context'), settings.max_context_bytes)
        report = run_suite(revision.source, body.cases, schema=revision.context_schema)
        suite = TestSuite(policy_id=revision.policy_id, name=body.name)
        svc.session.add(suite)
        svc.session.flush()
        for index, case in enumerate(body.cases):
            svc.session.add(TestCase(suite_id=suite.id, name=case.get('name', str(index + 1)),
                rule=case['rule'], context=case['context'], expect=case.get('expect', {'result': case.get('result')})))
        svc.session.add(TestRun(suite_id=suite.id, revision_id=revision.id, report=report))
        return report

    @app.get('/v2/projects/{project}/policies/{policy}/revisions/{number}/diff')
    def diff(project: str, policy: str, number: int, against: int, svc=Depends(service)):
        from rulea.quality import semantic_diff
        before = find_revision(svc, project, policy, against)
        after = find_revision(svc, project, policy, number)
        return semantic_diff(before.source, after.source)

    @app.get('/v2/projects/{project}/environments/{environment}')
    def environment(project: str, environment: str, response: Response, svc=Depends(service)):
        svc.require('policy:read')
        env = svc.environment(svc.project(project), environment)
        response.headers['ETag'] = f'"environment-{env.version}"'
        return {'key': env.key, 'version': env.version, 'required_approvals': env.required_approvals}

    @app.post('/v2/projects/{project}/deployments', status_code=201)
    def deployment(project: str, body: DeploymentInput, if_match: str | None = Header(default=None), svc=Depends(service)):
        d = svc.create_deployment(project, body.environment, body.items, etag(if_match, 'environment'), activate_at=body.activate_at)
        return {'deployment_id': d.id, 'status': d.status}

    @app.post('/v2/deployments/{deployment_id}/approve', status_code=204)
    def approve(deployment_id: str, svc=Depends(service)):
        svc.approve(deployment_id)
        return Response(status_code=204)

    @app.post('/v2/deployments/{deployment_id}/release')
    def release(deployment_id: str, svc=Depends(service)):
        return {'release_ids': [r.id for r in svc.release(deployment_id)]}

    @app.post('/v2/keys', status_code=201)
    def key(body: KeyInput, svc=Depends(service)):
        svc.require('admin:users')
        account = svc.session.scalar(select(ServiceAccount).where(ServiceAccount.workspace_id == svc.workspace_id,
                                                                   ServiceAccount.name == body.service_account))
        if account is None:
            account = ServiceAccount(workspace_id=svc.workspace_id, name=body.service_account)
            svc.session.add(account)
            svc.session.flush()
        record, value = issue_key(svc.session, service_account_id=account.id, human_id=svc.human_id,
            permissions=body.permissions, scope=body.scope, expires_at=body.expires_at)
        return {'key': value, 'prefix': record.prefix, 'expires_at': record.expires_at}

    def execute(item, token, workspace, session):
        size(item.context, settings.max_context_bytes)
        record, account = authenticate_key(session, token, permission='decision:execute',
            resource={'project': item.project, 'policy': item.policy, 'environment': item.environment})
        if account.workspace_id != workspace.id:
            raise Forbidden('Workspace does not match credential')
        return decide(session, workspace_id=workspace.id, service_account_id=account.id,
                      project_key=item.project, policy_key=item.policy, environment=item.environment,
                      rule=item.rule, context=item.context, trace=item.trace)

    @app.post('/v2/decisions')
    def decision(body: DecisionInput, token=Depends(bearer), workspace=Depends(workspace), session=Depends(db)):
        return execute(body, token, workspace, session)

    @app.post('/v2/decisions/batch')
    def batch(body: BatchInput, token=Depends(bearer), workspace=Depends(workspace), session=Depends(db)):
        if len(body.items) > settings.max_batch_size:
            raise HTTPException(413, 'Batch exceeds configured limit')
        return {'items': [execute(item, token, workspace, session) for item in body.items]}

    return app
