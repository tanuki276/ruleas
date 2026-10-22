"""Atomic, shared login budgets. Expensive password checks never hold bucket locks."""
import hashlib
import hmac
import math
from datetime import timedelta
from ipaddress import ip_address, ip_network

from sqlalchemy import case
from sqlalchemy.dialects.postgresql import insert
from .models import LoginBucket, now


class RateLimited(ValueError):
    def __init__(self, retry_after):
        super().__init__('Too many login attempts')
        self.retry_after = max(1, retry_after)


def client_ip(request, trusted_proxies):
    def address(value):
        # Zone identifiers are local interface metadata, not client identity.
        parsed = ip_address(value.split('%', 1)[0])
        return parsed.ipv4_mapped if getattr(parsed, 'ipv4_mapped', None) else parsed
    try:
        peer = address(request.client.host)
    except (ValueError, AttributeError):
        return 'unknown'
    networks = [ip_network(value) for value in trusted_proxies]
    def trusted(value):
        return any(value in network for network in networks)
    if not trusted(peer):
        return str(peer)
    parts = request.headers.get('x-forwarded-for', '').split(',')
    if len(parts) > 16:
        return str(peer)
    try:
        hops = [address(p.strip()) for p in parts]
    except ValueError:
        return str(peer)
    for hop in reversed(hops):
        if not trusted(peer):
            break
        peer = hop
    return str(peer)


def consume_login_budget(sessions, settings, ip, username):
    current = now()
    reset = current + timedelta(seconds=settings.login_window_seconds)
    blocked = None
    # The IP budget is checked first, so a blocked peer cannot exhaust other
    # users' username budgets. Commit denied attempts too, across all replicas.
    with sessions.begin() as session:
        for kind, value, limit in [('ip', ip, settings.login_ip_limit),
                                   ('username', username, settings.login_username_limit)]:
            key = hmac.new(settings.secret_key.get_secret_value().encode(),
                           (kind + ':' + value).encode(), hashlib.sha256).hexdigest()
            expired = LoginBucket.reset_at <= current
            stmt = insert(LoginBucket).values(key=key, count=1, reset_at=reset)
            count, reset_at = session.execute(stmt.on_conflict_do_update(index_elements=[LoginBucket.key],
                set_={'count': case((expired, 1), else_=case((LoginBucket.count < limit + 1, LoginBucket.count + 1), else_=limit + 1)),
                      'reset_at': case((expired, reset), else_=LoginBucket.reset_at)})
                .returning(LoginBucket.count, LoginBucket.reset_at)).one()
            if count > limit:
                blocked = RateLimited(math.ceil((reset_at - current).total_seconds()))
                break
    if blocked:
        raise blocked
