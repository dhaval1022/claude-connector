"""First-admin bootstrap from environment variables, for hosts where you have no shell.

  CONNECTOR_BOOTSTRAP_ADMIN_EMAIL, CONNECTOR_BOOTSTRAP_ADMIN_PASSWORD [, ..._NAME]

Safety rules (an env-var password must not become a standing backdoor):
- the account is created ONLY when there are no users at all, never again afterwards, and an
  existing user's password is never overwritten or reset from the environment;
- it must change the password at first sign-in, after which the env value no longer works;
- the password is never logged. Remove the variables once you have signed in.
"""
import logging

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError, ProgrammingError

from app.auth.passwords import hash_password
from app.config import get_settings
from app.db.models import User
from app.db.session import SessionLocal
from app.observability import log_event

MIN_PASSWORD = 10
log = logging.getLogger("connector")


async def ensure_bootstrap_admin() -> bool:
    """Returns True if an account was created."""
    s = get_settings()
    email = s.bootstrap_admin_email.strip().lower()
    password = s.bootstrap_admin_password
    if not email and not password:
        return False
    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise RuntimeError("CONNECTOR_BOOTSTRAP_ADMIN_EMAIL is not a valid email address.")
    if len(password) < MIN_PASSWORD:
        raise RuntimeError(f"CONNECTOR_BOOTSTRAP_ADMIN_PASSWORD must be at least "
                           f"{MIN_PASSWORD} characters.")
    try:
        async with SessionLocal() as db:
            if (await db.execute(select(func.count()).select_from(User))).scalar_one() > 0:
                return False
            db.add(User(email=email, name=s.bootstrap_admin_name.strip() or "Administrator",
                        role="admin", password_hash=hash_password(password),
                        must_change_password=True))
            await db.commit()
    except (OperationalError, ProgrammingError) as e:
        raise RuntimeError("The database is not initialised. Run the pre-deploy step first: "
                           "python -m app.cli migrate") from e
    log_event("bootstrap_admin_created", email=email)   # never the password
    return True
