"""Run Alembic migrations from code (CLI / tests). Synchronous on purpose: Alembic's async env
starts its own event loop, so never call this from inside a running loop."""
from pathlib import Path

from alembic import command
from alembic.config import Config


def _config(url: str | None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    if url:
        cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return cfg


def upgrade(url: str | None = None, revision: str = "head") -> None:
    command.upgrade(_config(url), revision)


def current(url: str | None = None) -> None:
    command.current(_config(url), verbose=True)
