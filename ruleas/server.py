"""Ruleas HTTP API and management console."""
import os
import secrets
import time
import math
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, text, case, delete as sql_delete
from sqlalchemy.exc import IntegrityError
from starlette.middleware.sessions import SessionMiddleware
from rulea import RuleEngine, PolicyError
from rulea.parser import parse_policy
from .storage import Base, User, APIKey, Policy, Revision, Audit, LoginBucket, connect, now
from .limits import BodyLimit, EngineCache, validate_context
from .security import hash_password, verify_password, key_digest

class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(max_length=1024)
class UserInput(Credentials):
    role: str = 'viewer'
class PolicyInput(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=262144)
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    expected_version: Optional[int] = None

    @field_validator('source')
    @classmethod
    def source_bytes(cls, value):
        if len(value.encode('utf-8')) > 262144:
            raise ValueError('source exceeds 256 KiB')
        return value

    @field_validator('tags')
    @classmethod
    def bounded_tags(cls, value):
        if len(value) > 32 or any(len(tag.encode('utf-8')) > 64 for tag in value):
            raise ValueError('At most 32 tags, each at most 64 UTF-8 bytes')
        return value
class Evaluation(BaseModel):
    policy_id: int
    rule: str = Field(min_length=1, max_length=256)
    context: dict = Field(default_factory=dict)
    @field_validator('context')
    @classmethod
    def bounded_context(cls, value):
        return validate_context(value)

class KeyInput(BaseModel):
    name: str = Field(min_length=1, max_length=128)

def snapshot(p):
    return {k: getattr(p, k) for k in ('name', 'source', 'namespace', 'enabled', 'tags', 'deleted')}
def output(p):
    return dict(snapshot(p), id=p.id, version=p.version, updated_at=p.updated_at.isoformat())

def create_app(database_url=None, secret_key=None, secure_cookie=None):
    url = database_url or os.environ.get('RULEAS_DATABASE_URL')
    secret = secret_key or os.environ.get('RULEAS_SECRET_KEY')
    if not url or not secret or len(secret) < 32:
        raise RuntimeError('Set RULEAS_DATABASE_URL and RULEAS_SECRET_KEY (at least 32 characters); run ruleas init-db first')
    engine, sessions = connect(url)
    cache = EngineCache()
    @asynccontextmanager
    async def lifespan(app):
        yield
        engine.dispose()
    app = FastAPI(title='Ruleas', version='1.0.0', lifespan=lifespan)
    app.add_middleware(SessionMiddleware, secret_key=secret, same_site='strict', https_only=secure_cookie if secure_cookie is not None else os.getenv('RULEAS_COOKIE_SECURE', 'true').lower() == 'true', max_age=28800)
    app.add_middleware(BodyLimit)
    def db():
        with sessions() as session:
            yield session
    def identity(request: Request, session=Depends(db)):
        header = request.headers.get('authorization', '')
        if header.startswith('Bearer '):
            key = session.scalar(select(APIKey).where(APIKey.digest == key_digest(header[7:]), APIKey.enabled.is_(True)))
            user = session.get(User, key.user_id) if key else None
        else:
            user = session.get(User, request.session.get('uid')) if request.session.get('uid') else None
            if user and request.method not in ('GET', 'HEAD') and not secrets.compare_digest(request.headers.get('x-csrf-token', ''), request.session.get('csrf', 'missing')):
                raise HTTPException(403, 'Invalid CSRF token')
        if not user:
            raise HTTPException(401, 'Authentication required')
        return user
    def admin(user=Depends(identity)):
        if user.role != 'admin':
            raise HTTPException(403, 'Administrator required')
        return user
    def get_policy(session, pid):
        p = session.scalar(select(Policy).where(Policy.id == pid, Policy.deleted.is_(False)))
        if not p:
            raise HTTPException(404, 'Policy not found')
        return p
    def get_policy_for_update(session, pid, include_deleted=False):
        query = select(Policy).where(Policy.id == pid)
        if not include_deleted:
            query = query.where(Policy.deleted.is_(False))
        p = session.scalar(query.with_for_update())
        if not p:
            raise HTTPException(404, 'Policy not found')
        return p
    def record(session, p, user, action):
        session.add(Revision(policy_id=p.id, version=p.version, snapshot=snapshot(p), actor=user.username))
        session.add(Audit(actor=user.username, action=action, policy_id=p.id, result='OK'))
        session.commit()
    def validate(source):
        try:
            RuleEngine.from_string(source)
            return parse_policy(source)['namespace']
        except (PolicyError, RecursionError) as exc:
            raise HTTPException(422, str(exc))
    @app.get('/health')
    def health(session=Depends(db)):
        try:
            session.execute(text('SELECT 1'))
        except Exception:
            raise HTTPException(503, 'Database unavailable')
        return {'status': 'ok', 'version': '1.0.0'}
    dummy_password = hash_password('dummy-password-for-timing')
    def login_limit(request, username):
        # Separate transaction: denied attempts and failed passwords still count.
        window = int(time.time()) // 60
        ip = request.client.host if request.client else 'unknown'
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        insert = pg_insert if engine.dialect.name == 'postgresql' else sqlite_insert
        denied = False
        with sessions() as throttle:
            for kind, value, maximum in [('ip', ip, 30), ('user', username, 10)]:
                key = key_digest(kind + ':' + value)
                stmt = insert(LoginBucket).values(key=key, window=window, count=1)
                stmt = stmt.on_conflict_do_update(index_elements=['key'], set_={
                    'window': window,
                    'count': case((LoginBucket.window == window, LoginBucket.count + 1), else_=1),
                }).returning(LoginBucket.count)
                denied = throttle.execute(stmt).scalar_one() > maximum or denied
            throttle.execute(sql_delete(LoginBucket).where(LoginBucket.window < window - 1))
            throttle.commit()
        if denied:
            raise HTTPException(429, 'Too many login attempts', headers={'Retry-After': str(max(1, math.ceil((window + 1) * 60 - time.time())))})

    @app.post('/v1/login')
    def login(data: Credentials, request: Request, session=Depends(db)):
        login_limit(request, data.username)
        user = session.scalar(select(User).where(User.username == data.username))
        if not verify_password(data.password, user.password if user else dummy_password) or not user:
            raise HTTPException(401, 'Invalid credentials')
        request.session.clear()
        request.session.update(uid=user.id, csrf=secrets.token_urlsafe(32))
        return {'username': user.username, 'role': user.role, 'csrf_token': request.session['csrf']}
    @app.get('/v1/me')
    def me(request: Request, user=Depends(identity)):
        return {'username': user.username, 'role': user.role, 'csrf_token': request.session.get('csrf')}
    @app.post('/v1/logout')
    def logout(request: Request, user=Depends(identity)):
        request.session.clear()
        return {'ok': True}
    @app.post('/v1/users', status_code=201)
    def add_user(data: UserInput, user=Depends(admin), session=Depends(db)):
        if data.role not in ('admin', 'viewer'):
            raise HTTPException(422, 'role must be admin or viewer')
        try:
            obj = User(username=data.username, password=hash_password(data.password), role=data.role)
            session.add(obj)
            session.commit()
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        except IntegrityError:
            session.rollback()
            raise HTTPException(409, 'Username already exists')
        return {'id': obj.id, 'username': obj.username, 'role': obj.role}
    @app.post('/v1/api-keys', status_code=201)
    def add_key(data: KeyInput, user=Depends(admin), session=Depends(db)):
        token = 'rs_' + secrets.token_urlsafe(32)
        key = APIKey(user_id=user.id, name=data.name, digest=key_digest(token))
        session.add(key)
        session.commit()
        return {'id': key.id, 'key': token}
    @app.get('/v1/api-keys')
    def keys(user=Depends(admin), session=Depends(db)):
        return [{'id': k.id, 'name': k.name, 'enabled': k.enabled} for k in session.scalars(select(APIKey).where(APIKey.user_id == user.id))]
    @app.delete('/v1/api-keys/{kid}')
    def revoke(kid: int, user=Depends(admin), session=Depends(db)):
        k = session.get(APIKey, kid)
        if not k or k.user_id != user.id:
            raise HTTPException(404, 'Key not found')
        k.enabled = False
        session.commit()
        return {'ok': True}
    @app.get('/v1/rules')
    def rules(user=Depends(identity), session=Depends(db)):
        return [output(p) for p in session.scalars(select(Policy).where(Policy.deleted.is_(False)).order_by(Policy.id))]
    @app.get('/v1/rules/{pid}')
    def get_rule(pid: int, user=Depends(identity), session=Depends(db)):
        return output(get_policy(session, pid))
    @app.get('/v1/rules/{pid}/source')
    def source(pid: int, user=Depends(identity), session=Depends(db)):
        return Response(get_policy(session, pid).source, media_type='text/plain', headers={'Content-Disposition': 'attachment; filename="policy.rulea"'})
    @app.post('/v1/rules', status_code=201)
    def create(data: PolicyInput, user=Depends(admin), session=Depends(db)):
        namespace = validate(data.source)
        p = Policy(name=data.name, source=data.source, namespace=namespace, enabled=data.enabled, tags=data.tags, deleted=False, version=1)
        session.add(p)
        try:
            session.flush()
            record(session, p, user, 'create')
        except IntegrityError:
            session.rollback()
            raise HTTPException(409, 'Policy name already exists')
        return output(p)
    @app.put('/v1/rules/{pid}')
    def update(pid: int, data: PolicyInput, user=Depends(admin), session=Depends(db)):
        namespace = validate(data.source)
        p = get_policy_for_update(session, pid)
        if data.expected_version is None or p.version != data.expected_version:
            raise HTTPException(409, 'Supply current expected_version')
        p.name, p.source, p.namespace, p.enabled, p.tags = data.name, data.source, namespace, data.enabled, data.tags
        p.version += 1
        p.updated_at = now()
        try:
            record(session, p, user, 'update')
        except IntegrityError:
            session.rollback()
            raise HTTPException(409, 'Policy name already exists')
        return output(p)
    @app.delete('/v1/rules/{pid}')
    def delete(pid: int, user=Depends(admin), session=Depends(db)):
        p = get_policy_for_update(session, pid)
        p.deleted = True
        p.version += 1
        p.updated_at = now()
        record(session, p, user, 'delete')
        return {'ok': True}
    @app.get('/v1/rules/{pid}/versions')
    def versions(pid: int, user=Depends(identity), session=Depends(db)):
        return [{'version': r.version, 'snapshot': r.snapshot, 'actor': r.actor, 'created_at': r.created_at.isoformat()} for r in session.scalars(select(Revision).where(Revision.policy_id == pid).order_by(Revision.version.desc()))]
    @app.post('/v1/rules/{pid}/rollback/{version}')
    def rollback(pid: int, version: int, user=Depends(admin), session=Depends(db)):
        p = get_policy_for_update(session, pid, include_deleted=True)
        r = session.scalar(select(Revision).where(Revision.policy_id == pid, Revision.version == version))
        if not p or not r:
            raise HTTPException(404, 'Version not found')
        validate(r.snapshot['source'])
        for k, v in r.snapshot.items():
            setattr(p, k, v)
        p.version += 1
        p.updated_at = now()
        record(session, p, user, 'rollback')
        return output(p)
    def evaluate(data, user, session):
        p = get_policy(session, data.policy_id)
        eng = cache.get(p)
        if p.enabled:
            decision = eng.decide(data.rule, data.context).to_dict()
        else:
            decision = {'result': 'NOT_APPLICABLE', 'rule': data.rule, 'reason': 'Policy disabled', 'policy_version': eng.policy_version, 'policy_hash': eng.policy_hash, 'engine_version': '1.0.0', 'trace': [], 'decisions': []}
        session.add(Audit(actor=user.username, action='execute', policy_id=p.id, rule=data.rule, result=decision['result'], policy_hash=decision['policy_hash'], engine_version=decision['engine_version']))
        session.commit()
        return decision
    @app.post('/v1/decide')
    def decide(data: Evaluation, user=Depends(identity), session=Depends(db)):
        return evaluate(data, user, session)
    @app.post('/v1/check')
    def check(data: Evaluation, user=Depends(identity), session=Depends(db)):
        d = evaluate(data, user, session)
        return {'allowed': d['result'] == 'ALLOW', 'reason': None if d['result'] == 'ALLOW' else d['reason'], 'decision': d}
    @app.get('/v1/audit-logs')
    def audits(limit: int = 100, user=Depends(admin), session=Depends(db)):
        return [{k: getattr(a, k) for k in ('id', 'actor', 'action', 'policy_id', 'rule', 'result', 'policy_hash', 'engine_version', 'created_at')} for a in session.scalars(select(Audit).order_by(Audit.id.desc()).limit(max(1, min(limit, 1000))))]
    @app.get('/', response_class=HTMLResponse)
    def console():
        return Path(__file__).with_name('admin.html').read_text(encoding='utf-8')
    return app
