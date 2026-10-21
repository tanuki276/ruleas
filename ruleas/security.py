import base64
import hashlib
import hmac
import secrets

def hash_password(password):
    if len(password) < 12:
        raise ValueError('Password must contain at least 12 characters')
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return base64.b64encode(salt + digest).decode()

def verify_password(password, encoded):
    try:
        raw = base64.b64decode(encoded)
        return hmac.compare_digest(raw[16:], hashlib.scrypt(password.encode(), salt=raw[:16], n=16384, r=8, p=1))
    except (ValueError, TypeError):
        return False

def key_digest(value):
    return hashlib.sha256(value.encode()).hexdigest()
