"""Human sessions and machine credentials use separate, hashed bearer tokens."""
import base64
import hashlib
import hmac
import secrets
import logging
import re
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select, update, or_
from sqlalchemy.exc import SQLAlchemyError
from .models import APIKey, AuthSession, ServiceAccount, now
from .service import Forbidden, PERMISSIONS


class Unauthenticated(ValueError):
    """No valid credential for the requested authentication scheme."""


ACTIVITY_INTERVAL = timedelta(seconds=60)
SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
_logger = logging.getLogger(__name__)

_hasher = PasswordHasher()


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password):
    if len(password) < 12:
        raise ValueError('Password must contain at least 12 characters')
    return _hasher.hash(password)


def verify_password(password, encoded):
    """Return (valid, replacement_hash); rehash legacy scrypt only after success."""
    if encoded.startswith('$argon2id$'):
        try:
            _hasher.verify(encoded, password)
            return True, _hasher.hash(password) if _hasher.check_needs_rehash(encoded) else None
        except (VerificationError, InvalidHashError):
            return False, None
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 80:
            return False, None
        valid = hmac.compare_digest(raw[16:], hashlib.scrypt(password.encode(), salt=raw[:16], n=16384, r=8, p=1))
        return valid, _hasher.hash(password) if valid else None
    except (ValueError, TypeError):
        return False, None


def issue_session(session, human_id, *, expires_at=None):
    token = 'rhs_' + secrets.token_urlsafe(32)
    session.add(AuthSession(human_id=human_id, digest=token_digest(token), expires_at=expires_at or now() + timedelta(hours=12)))
    return token


def authenticate_human(session, token):
    if not re.fullmatch(r'rhs_[A-Za-z0-9_-]{43}', token):
        raise Unauthenticated('Session expired or invalid')
    record = session.scalar(select(AuthSession).where(AuthSession.digest == token_digest(token)))
    current = now()
    if record is None or record.revoked_at or record.expires_at <= current or record.last_used_at + SESSION_IDLE_TIMEOUT <= current:
        raise Unauthenticated('Session expired or invalid')
    return record


def rotate_session(session, record):
    # Serialize rare rotation/logout operations by human, never ordinary reads.
    from .models import Human
    session.execute(select(Human.id).where(Human.id == record.human_id).with_for_update()).one()
    current = now()
    changed = session.execute(update(AuthSession).where(AuthSession.id == record.id,
        AuthSession.revoked_at.is_(None), AuthSession.expires_at > current,
        AuthSession.last_used_at > current - SESSION_IDLE_TIMEOUT).values(revoked_at=current))
    if changed.rowcount != 1:
        raise Unauthenticated('Session expired or invalid')
    return issue_session(session, record.human_id, expires_at=record.expires_at)


def logout_all_sessions(session, record):
    from .models import Human
    session.execute(select(Human.id).where(Human.id == record.human_id).with_for_update()).one()
    session.execute(update(AuthSession).where(AuthSession.human_id == record.human_id).values(revoked_at=now()))


def touch_activity(sessions, kind, identifier):
    """Best-effort, bounded telemetry after the response; never wait for a busy credential.

    Session idle activity has minute resolution and may expire up to a minute
    earlier than the last actual request. Absolute expiry is never extended.
    """
    model = {'session': AuthSession, 'key': APIKey}[kind]
    current = now()
    try:
        with sessions.begin() as session:
            session.connection().exec_driver_sql("SET LOCAL statement_timeout = '100ms'")
            row = session.scalar(select(model).where(model.id == identifier,
                model.revoked_at.is_(None), model.expires_at > current,
                or_(model.last_used_at.is_(None), model.last_used_at <= current - ACTIVITY_INTERVAL))
                .with_for_update(skip_locked=True))
            if row is not None:
                row.last_used_at = current
    except SQLAlchemyError:
        _logger.warning('credential_activity_write_failed', extra={'credential_type': kind})


def issue_key(session, *, service_account_id, human_id, permissions, scope, expires_at):
    if not permissions or not set(permissions) <= PERMISSIONS:
        raise ValueError('Unknown or empty permission set')
    if set(scope) - {'project', 'environment', 'policy'}:
        raise ValueError('Unknown resource scope')
    if ('policy' in scope or 'environment' in scope) and 'project' not in scope:
        raise ValueError('Policy/environment scopes require a project')
    if expires_at.utcoffset() is None or expires_at <= now():
        raise ValueError('Expiry must be a future timezone-aware timestamp')
    value = 'rk_' + secrets.token_urlsafe(32)
    record = APIKey(service_account_id=service_account_id, created_by=human_id, digest=token_digest(value),
                    prefix=value[:12], permissions=sorted(set(permissions)), resource_scope=scope, expires_at=expires_at)
    session.add(record)
    session.flush()
    return record, value


def authenticate_key(session, token, *, permission=None, resource=None):
    if not re.fullmatch(r'rk_[A-Za-z0-9_-]{43}', token):
        raise Unauthenticated('Credential expired or invalid')
    record = session.scalar(select(APIKey).where(APIKey.digest == token_digest(token)))
    if record is None or record.revoked_at or record.expires_at <= now():
        raise Unauthenticated('Credential expired or invalid')
    account = session.get(ServiceAccount, record.service_account_id)
    if account is None or not account.enabled:
        raise Unauthenticated('Credential expired or invalid')
    if permission is not None:
        authorize_key(record, permission, resource or {})
    return record, account


def authorize_key(record, permission, resource):
    if permission not in record.permissions:
        raise Forbidden('Permission denied')
    if any(resource.get(k) != v for k, v in record.resource_scope.items()):
        raise Forbidden('Credential resource scope does not match')
