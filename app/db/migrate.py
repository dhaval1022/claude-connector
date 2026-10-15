"""Direct database schema creation without Alembic."""
import asyncio

from app.config import get_settings
from app.db.init_db import create_schema


def upgrade(url: str | None = None, revision: str = "head") -> None:
    create_schema(url)


def stamp(url: str | None = None, revision: str = "head") -> None:
    pass


def current(url: str | None = None) -> None:
    pass


async def auto_upgrade(url: str | None = None) -> None:
    """Create schema directly at server startup without Alembic."""
    target_url = url or get_settings().database_url
    await asyncio.to_thread(create_schema, target_url)


