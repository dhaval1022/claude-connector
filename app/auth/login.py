"""Shared credential check with lockout, used by the OAuth sign-in page and the web UI."""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.passwords import verify_password
from app.auth.tokens import aware
from app.db.models import User

MIN_PASSWORD_LEN = 10


async def authenticate(db: AsyncSession, email: str, password: str) -> tuple[User | None, str]:
    """Returns (user, "") on success or (None, error message)."""
    user = (await db.execute(select(User).where(
        User.email == email.strip().lower(),
        User.deleted_at.is_(None)))
    ).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if user and user.locked_until and aware(user.locked_until) > now:
        return None, "Account temporarily locked. Try later."
    if not user or not user.is_active or not verify_password(password, user.password_hash):
        return None, "Invalid email or password."
    user.locked_until, user.last_login = None, now
    await db.commit()
    return user, ""
