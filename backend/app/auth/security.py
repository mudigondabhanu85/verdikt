import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.config import get_settings
from app.models.api_key import API_KEY_PREFIX

_pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return _pwd_context.verify(password, hashed_password)


def create_access_token(user_id: uuid.UUID) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> uuid.UUID:
    settings = get_settings()
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    return uuid.UUID(payload["sub"])


def generate_api_key() -> tuple[str, str, str]:
    """Returns (raw_key, key_prefix, hashed_key). raw_key is shown to the
    caller exactly once — only key_prefix and hashed_key get persisted.
    """
    raw_key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    key_prefix = raw_key[:12]
    return raw_key, key_prefix, hash_api_key(raw_key)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()
