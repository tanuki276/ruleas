"""Human sessions and machine credentials use separate, hashed bearer tokens."""
import base64
import hashlib
import hmac
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select
from .models import APIKey, AuthSession, ServiceAccount, now
from .service import Forbidden, PERMISSIONS

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
    record = session.scalar(select(AuthSession).where(AuthSession.digest == token_digest(token)).with_for_update())
    current = now()
    if record is None or record.revoked_at or record.expires_at <= current or record.last_used_at + timedelta(minutes=30) <= current:
        raise Forbidden('Session expired or invalid')
    record.last_used_at = current
    return record


def issue_key(session, *, service_account_id, human_id, permissions, scope, expires_at):
    if not permissions or not set(permissions) <= PERMISSIONS:
        raise ValueError('Unknown or empty permission set')
    if set(scope) - {'project', 'environment', 'policy'}:
        raise ValueError('Unknown resource scope')
    if expires_at.utcoffset() is None or expires_at <= now():
        raise ValueError('Expiry must be a future timezone-aware timestamp')
    value = 'rk_' + secrets.token_urlsafe(32)
    record = APIKey(service_account_id=service_account_id, created_by=human_id, digest=token_digest(value),
                    prefix=value[:12], permissions=sorted(set(permissions)), resource_scope=scope, expires_at=expires_at)
    session.add(record)
    session.flush()
    return record, value


def authenticate_key(session, token, *, permission, resource):
    record = session.scalar(select(APIKey).where(APIKey.digest == token_digest(token)))
    if record is None or record.revoked_at or record.expires_at <= now():
        raise Forbidden('Credential expired or invalid')
    account = session.get(ServiceAccount, record.service_account_id)
    if account is None or not account.enabled or permission not in record.permissions:
        raise Forbidden('Permission denied')
    if any(resource.get(k) != v for k, v in record.resource_scope.items()):
        raise Forbidden('Credential resource scope does not match')
    record.last_used_at = now()
    return record, account
