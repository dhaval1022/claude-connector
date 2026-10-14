"""Single entry point for building connectors by engine name."""
import shutil
from pathlib import Path

from app.config import get_settings
from app.connectors.athena import AthenaConnector
from app.connectors.duck import DuckConnector
from app.connectors.sql import DIALECTS, SqlConnector


def make_connector(source_id: str, engine: str, cfg: dict):
    if engine == "files":
        return DuckConnector(source_id, cfg)
    if engine == "athena":
        return AthenaConnector(source_id, cfg)
    if engine == "sqlite" and not get_settings().enable_sqlite:
        raise ValueError("SQLite is disabled.")
    if engine not in DIALECTS:
        raise ValueError(f"Unsupported engine '{engine}'")
    return SqlConnector(source_id, engine, cfg)


def source_dir(owner_id: str, source_id: str) -> Path:
    return Path(get_settings().data_dir).resolve() / owner_id / source_id


def dispose(source_id: str, engine: str | None = None, owner_id: str | None = None) -> None:
    SqlConnector.dispose(source_id)
    if engine == "files" and owner_id:
        shutil.rmtree(source_dir(owner_id, source_id), ignore_errors=True)
