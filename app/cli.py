"""Operations CLI.

  python -m app.cli gen-key                         new CONNECTOR_MASTER_KEY value
  python -m app.cli gen-secret                      new CONNECTOR_JWT_SECRET value
  python -m app.cli migrate                         create/upgrade the metadata database
  python -m app.cli create-admin EMAIL NAME PASSWORD
  python -m app.cli rotate-key OLD_KEY NEW_KEY [--dry-run]
"""
import asyncio
import secrets
import sys

from sqlalchemy import select

from app.auth.passwords import hash_password
from app.db.models import User
from app.db.session import SessionLocal

MIN_PASSWORD = 10


async def _create_admin(email: str, name: str, password: str) -> None:
    async with SessionLocal() as s:
        if (await s.execute(select(User).where(User.email == email.lower()))).scalar_one_or_none():
            sys.exit(f"User {email} already exists")
        s.add(User(email=email.lower(), name=name, role="admin",
                   password_hash=hash_password(password)))
        await s.commit()
    print(f"Admin {email} created.")


def main(argv: list[str]) -> None:
    cmd = argv[0] if argv else ""
    if cmd == "gen-key" and len(argv) == 1:
        from app.sources.crypto import generate_key
        print(generate_key())
    elif cmd == "gen-secret" and len(argv) == 1:
        print(secrets.token_urlsafe(48))
    elif cmd == "migrate" and len(argv) == 1:
        from app.db.migrate import upgrade
        upgrade()                       # sync: Alembic runs its own event loop
        print("Database is up to date.")
    elif cmd == "create-admin" and len(argv) == 4:
        if len(argv[3]) < MIN_PASSWORD or "@" not in argv[1]:
            sys.exit(f"Use a valid email and a password of at least {MIN_PASSWORD} characters.")
        from app.db.migrate import upgrade
        upgrade()
        asyncio.run(_create_admin(*argv[1:4]))
    elif cmd == "rotate-key" and len(argv) in (3, 4) and (len(argv) == 3 or argv[3] == "--dry-run"):
        from app.sources.rotation import RotationError, rotate_master_key
        try:
            n = asyncio.run(rotate_master_key(argv[1], argv[2], dry_run=len(argv) == 4))
        except (RotationError, RuntimeError) as e:
            sys.exit(f"ERROR: {e}")
        if len(argv) == 4:
            print(f"Dry run OK: {n} data source(s) could be re-encrypted. Nothing was changed.")
        else:
            print(f"Re-encrypted {n} data source(s). Now set CONNECTOR_MASTER_KEY to the NEW "
                  "key and restart the server.")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
