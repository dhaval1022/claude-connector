import hashlib
import secrets
import time
from datetime import datetime, timezone

import jwt

from app.config import get_settings


def random_token() -> str:
    return secrets.token_urlsafe(48)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; treat them as UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _audience() -> str:
    return get_settings().public_base_url.rstrip("/") + "/mcp"


def issue_access_token(user_id: str, client_id: str, provider: str = "claude") -> str:
    """`prv` = which AI provider this sign-in was for (app/providers.py). It is signed, so a
    client cannot change it; tokens issued before providers existed have no `prv` and are
    treated as Claude's."""
    s = get_settings()
    now = int(time.time())
    return jwt.encode(
        {"sub": user_id, "cid": client_id, "prv": provider, "iat": now,
         "exp": now + s.access_token_ttl_s, "aud": _audience()},
        s.jwt_secret, algorithm="HS256",
    )


def verify_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"],
                          audience=_audience())
    except jwt.PyJWTError:
        return None
