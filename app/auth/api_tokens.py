"""Personal API tokens: static bearer tokens for MCP clients that cannot run our OAuth flow
(OpenAI's Responses API `authorization` field, Gemini CLI builds without MCP OAuth, scripts).

Security properties: 256-bit random secret, only its SHA-256 is stored, shown exactly once,
mandatory expiry, revocable, limited per user, dead the moment the owner is disabled. A token acts
as ITS OWNER ONLY, so never paste one into something shared (e.g. a Custom GPT used by others)."""
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import aware, sha256
from app.db.models import ApiToken, User
from app.providers import PROVIDERS

PREFIX = "mk_"
MAX_ACTIVE = 10
LIFETIMES_DAYS = (30, 90, 365)
LAST_USED_GRANULARITY = timedelta(minutes=5)     # avoid a database write on every call


class TokenError(ValueError):
    """Safe-to-display message."""


def looks_like_token(value: str) -> bool:
    return value.startswith(PREFIX) and 20 <= len(value) <= 128


def _active_filter(now: datetime):
    return (ApiToken.revoked.is_(False), ApiToken.expires_at > now)


async def create_token(db: AsyncSession, owner: User, name: str, provider: str,
                       days: int) -> tuple[str, ApiToken]:
    """Returns (plaintext, row). The plaintext is never retrievable again."""
    name = name.strip()
    if not name or len(name) > 80:
        raise TokenError("Give the token a name (max 80 characters), e.g. 'my Gemini CLI'.")
    if provider not in PROVIDERS:
        raise TokenError("Choose which app this token is for.")
    if days not in LIFETIMES_DAYS:
        raise TokenError(f"Lifetime must be one of {', '.join(map(str, LIFETIMES_DAYS))} days.")
    now = datetime.now(timezone.utc)
    active = (await db.execute(select(func.count()).select_from(ApiToken).where(
        ApiToken.owner_id == owner.id, *_active_filter(now)))).scalar_one()
    if active >= MAX_ACTIVE:
        raise TokenError(f"You already have {MAX_ACTIVE} active tokens. Revoke one first.")
    plain = PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(owner_id=owner.id, name=name, provider=provider, token_hash=sha256(plain),
                   prefix=plain[:8], expires_at=now + timedelta(days=days))
    db.add(row)
    await db.commit()
    return plain, row


async def authenticate_token(db: AsyncSession, plain: str) -> tuple[User, ApiToken] | None:
    """The owner and token row if the token is valid right now, else None."""
    if not looks_like_token(plain):
        return None
    row = (await db.execute(select(ApiToken).where(
        ApiToken.token_hash == sha256(plain)))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if not row or row.revoked or aware(row.expires_at) <= now:
        return None
    user = await db.get(User, row.owner_id)
    if not user or not user.is_active:
        return None
    if row.last_used_at is None or now - aware(row.last_used_at) > LAST_USED_GRANULARITY:
        row.last_used_at = now
        await db.commit()
    return user, row


async def list_tokens(db: AsyncSession, owner_id: str) -> list[ApiToken]:
    return list((await db.execute(select(ApiToken).where(ApiToken.owner_id == owner_id)
                                  .order_by(ApiToken.created_at.desc()))).scalars())


async def revoke_token(db: AsyncSession, owner_id: str, token_id: str) -> bool:
    row = (await db.execute(select(ApiToken).where(
        ApiToken.id == token_id, ApiToken.owner_id == owner_id))).scalar_one_or_none()
    if not row:
        return False
    row.revoked = True
    await db.commit()
    return True
