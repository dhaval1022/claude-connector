"""Initialize complete database structure safely without Alembic.

Usage:
    python init_db.py
"""
import sys
from pathlib import Path

from sqlalchemy import create_engine

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.auth.passwords import hash_password
from app.config import get_settings
from app.db.models import (
    ApiToken,
    AuditLog,
    Base,
    DataSource,
    Export,
    OAuthClient,
    OAuthCode,
    RefreshToken,
    SemanticItem,
    User,
)


def to_sync_url(raw_url: str) -> str:
    """Convert async driver URL to synchronous driver URL for schema management."""
    return (
        raw_url.replace("sqlite+aiosqlite:", "sqlite:")
        .replace("postgresql+asyncpg:", "postgresql+psycopg2:")
        .replace("postgresql+psycopg:", "postgresql+psycopg2:")
        .replace("mysql+aiomysql:", "mysql+pymysql:")
    )


def create_schema(sync_url: str | None = None):
    """Safely create all tables and indexes if they do not exist (non-destructive)."""
    settings = get_settings()
    raw_url = sync_url or settings.database_url
    sync_engine_url = to_sync_url(raw_url)
    print(f"Ensuring tables exist on: {sync_engine_url}")
    engine = create_engine(sync_engine_url)
    Base.metadata.create_all(engine, checkfirst=True)
    engine.dispose()
    print("Tables verified / created successfully:")
    for t in Base.metadata.sorted_tables:
        print(f"  - {t.name}")


def seed_bootstrap_admin(sync_url: str | None = None):
    """Create initial admin account if configured in environment."""
    from sqlalchemy.orm import Session
    settings = get_settings()
    email = settings.bootstrap_admin_email.strip().lower()
    password = settings.bootstrap_admin_password
    if not email or not password:
        return

    raw_url = sync_url or settings.database_url
    sync_engine_url = to_sync_url(raw_url)
    engine = create_engine(sync_engine_url)
    with Session(engine) as s:
        existing = s.query(User).filter(User.email == email).first()
        if not existing:
            admin = User(
                email=email,
                name=settings.bootstrap_admin_name.strip() or "Administrator",
                role="admin",
                password_hash=hash_password(password),
                allowed_providers=["claude", "openai", "gemini", "other"],
                is_active=True,
            )
            s.add(admin)
            s.commit()
            print(f"Created bootstrap admin: {email} (ID: {admin.id})")
        else:
            existing.password_hash = hash_password(password)
            existing.is_active = True
            existing.locked_until = None
            s.commit()
            print(f"Updated bootstrap admin credentials: {email} (ID: {existing.id})")
    engine.dispose()


def init_db(sync_url: str | None = None):
    create_schema(sync_url)
    seed_bootstrap_admin(sync_url)
    print("Database initialization complete.")


if __name__ == "__main__":
    init_db()
