import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.connectors import registry
from app.connectors.duck import FileLoadError, build_database
from app.connectors.registry import make_connector
from app.connectors.sql import SqlConnector
from app.db.models import DataSource
from app.sources.crypto import decrypt_config, encrypt_config
from app.sources.netcheck import HostBlocked, check_host

ENGINE_LABELS = {"files": "CSV / Excel files", "athena": "Amazon Athena", "postgres": "PostgreSQL", "mysql": "MySQL / MariaDB", "mssql": "SQL Server",
                 "sqlite": "SQLite (dev)"}
SECRET_KEYS = ("password", "secret_access_key", "session_token")


class SourceError(ValueError):
    """Safe-to-display error."""


def available_engines() -> dict[str, str]:
    return {k: v for k, v in ENGINE_LABELS.items()
            if k != "files" and (k != "sqlite" or get_settings().enable_sqlite)}


def clean_error(e: Exception, cfg: dict | None = None) -> str:
    """First line of a driver error, with any credentials scrubbed."""
    msg = (str(e).strip().splitlines() or [type(e).__name__])[0]
    for k in SECRET_KEYS:
        if cfg and cfg.get(k):
            msg = msg.replace(str(cfg[k]), "***")
    return msg[:400]


def parse_config(engine: str, form: dict) -> dict:
    if engine not in available_engines():
        raise SourceError("Unsupported database engine.")
    if engine == "sqlite":
        if not form.get("database"):
            raise SourceError("Database file path is required.")
        return {"database": form["database"].strip()}
    if engine == "athena":
        return _parse_athena(form)
    host = (form.get("host") or "").strip()
    if not host or not re.fullmatch(r"[A-Za-z0-9._\-:\[\]]+", host):
        raise SourceError("Enter a valid host name or IP address.")
    port = (form.get("port") or "").strip()
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        raise SourceError("Port must be a number between 1 and 65535.")
    if not (form.get("database") or "").strip():
        raise SourceError("Database name is required.")
    if not (form.get("username") or "").strip():
        raise SourceError("Username is required.")
    cfg = {"host": host, "port": int(port) if port else None,
           "database": form["database"].strip(), "username": form["username"].strip(),
           "password": form.get("password") or ""}
    if engine == "mssql":
        cfg["trust_server_cert"] = bool(form.get("trust_server_cert"))
    return cfg


def _parse_athena(form: dict) -> dict:
    from app.connectors.athena import REGION_RE
    region = (form.get("region") or "").strip()
    if not REGION_RE.match(region):
        raise SourceError("Enter a valid AWS region, e.g. ap-south-1.")
    s3 = (form.get("s3_output") or "").strip()
    if not re.fullmatch(r"s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](/[^\s]*)?", s3):
        raise SourceError("Query results location must look like s3://bucket/prefix/.")
    db = (form.get("database") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{1,128}", db):
        raise SourceError("Database must be a Glue database name (letters, digits, underscore).")
    wg = (form.get("workgroup") or "primary").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,128}", wg):
        raise SourceError("Invalid workgroup name.")
    key, secret = (form.get("access_key_id") or "").strip(), form.get("secret_access_key") or ""
    if bool(key) != bool(secret):
        raise SourceError("Provide both the access key id and secret, or neither "
                          "(to use the server's IAM role).")
    cfg = {"region": region, "s3_output": s3, "database": db, "workgroup": wg}
    if key:
        cfg.update(access_key_id=key, secret_access_key=secret)
    return cfg


async def create_source(db: AsyncSession, owner_id: str, name: str, engine: str,
                        cfg: dict) -> DataSource:
    name = name.strip()
    if not name or len(name) > 120:
        raise SourceError("Name is required (max 120 characters).")
    exists = (await db.execute(select(DataSource.id).where(
        DataSource.owner_id == owner_id, DataSource.name == name))).first()
    if exists:
        raise SourceError(f"You already have a data source named '{name}'.")
    source_id = uuid.uuid4().hex
    try:
        if "host" in cfg:
            check_host(cfg["host"])
        conn = make_connector(source_id, engine, cfg)
        await conn.test()
        schema = await conn.introspect()
    except HostBlocked as e:
        raise SourceError(str(e))
    except Exception as e:  # driver errors: scrub credentials
        SqlConnector.dispose(source_id)
        raise SourceError(f"Connection failed: {clean_error(e, cfg)}")
    src = DataSource(id=source_id, owner_id=owner_id, name=name, engine=engine,
                     config_encrypted=encrypt_config(cfg, source_id), status="ok",
                     schema_cache=schema, schema_cached_at=datetime.now(timezone.utc))
    db.add(src)
    await db.commit()
    return src


async def get_owned(db: AsyncSession, owner_id: str, source_id: str) -> DataSource | None:
    """The only way tools/UI load a source: always scoped to the owner."""
    return (await db.execute(select(DataSource).where(
        DataSource.id == source_id, DataSource.owner_id == owner_id))).scalar_one_or_none()


def connector_for(src: DataSource):
    cfg = decrypt_config(src.config_encrypted, src.id)
    if src.engine == "files":
        cfg["schema"] = src.schema_cache  # files are immutable: the cache is the schema
    return make_connector(src.id, src.engine, cfg)


async def refresh_schema(db: AsyncSession, src: DataSource) -> dict:
    conn = connector_for(src)
    try:
        schema = await conn.introspect()
    except Exception as e:
        src.status = "error"
        await db.commit()
        raise SourceError(f"Schema refresh failed: {clean_error(e, getattr(conn, 'cfg', None))}")
    src.schema_cache, src.schema_cached_at, src.status = schema, datetime.now(timezone.utc), "ok"
    await db.commit()
    return schema


async def delete_source(db: AsyncSession, owner_id: str, source_id: str) -> bool:
    src = await get_owned(db, owner_id, source_id)
    if not src:
        return False
    await db.delete(src)
    await db.commit()
    registry.dispose(source_id, src.engine, owner_id)
    return True


def flat_tables(schema_cache: dict | None) -> list[tuple[str, str, dict]]:
    """[(schema, table, info)] from a schema cache."""
    out = []
    for sch, tables in ((schema_cache or {}).get("schemas") or {}).items():
        for t, info in tables.items():
            out.append((sch, t, info))
    return out


def find_table(schema_cache: dict | None, ref: str) -> tuple[str, str, dict] | None:
    """Resolve 'table' or 'schema.table' case-insensitively; prefers the default schema."""
    sch_part, _, tbl = ref.rpartition(".")
    default = ((schema_cache or {}).get("default_schema") or "").lower()
    matches = [(s, t, i) for s, t, i in flat_tables(schema_cache)
               if t.lower() == tbl.lower() and (not sch_part or s.lower() == sch_part.lower())]
    matches.sort(key=lambda m: m[0].lower() != default)
    return matches[0] if matches else None


async def create_file_source(db: AsyncSession, owner_id: str, name: str,
                             files: list[tuple[str, "object"]]) -> DataSource:
    """files: [(original filename, async-readable upload with .read(n))]. Files are streamed to
    disk under the size cap, loaded into a DuckDB database, and never executed."""
    s = get_settings()
    name = name.strip()
    if not name or len(name) > 120:
        raise SourceError("Name is required (max 120 characters).")
    if not files:
        raise SourceError("Choose at least one CSV or Excel file.")
    if len(files) > s.max_upload_files:
        raise SourceError(f"At most {s.max_upload_files} files per data source.")
    if (await db.execute(select(DataSource.id).where(
            DataSource.owner_id == owner_id, DataSource.name == name))).first():
        raise SourceError(f"You already have a data source named '{name}'.")
    source_id = uuid.uuid4().hex
    folder = registry.source_dir(owner_id, source_id)
    folder.mkdir(parents=True, exist_ok=True)
    limit = s.max_upload_mb * 1024 * 1024
    saved = []
    try:
        for i, (orig, up) in enumerate(files):
            ext = ("." + orig.rsplit(".", 1)[-1].lower()) if "." in orig else ""
            if ext not in (".csv", ".txt", ".xlsx", ".xlsm"):
                raise SourceError(f"'{orig}': only .csv and .xlsx files are supported.")
            stem = re.sub(r"[^A-Za-z0-9_-]+", "_", orig.rsplit(".", 1)[0])[:60] or f"file{i}"
            path = folder / f"{stem}{ext}"  # server-chosen name; never the raw upload name
            size = 0
            with open(path, "wb") as out:
                while chunk := await up.read(1024 * 1024):
                    size += len(chunk)
                    if size > limit:
                        raise SourceError(f"'{orig}' exceeds the {s.max_upload_mb} MB limit.")
                    out.write(chunk)
            if size == 0:
                raise SourceError(f"'{orig}' is empty.")
            saved.append(path)
        import asyncio
        schema = await asyncio.to_thread(build_database, folder / "data.duckdb", saved)
        cfg = {"db_path": str(folder / "data.duckdb"), "schema": schema}
        conn = make_connector(source_id, "files", cfg)
        await conn.test()
    except FileLoadError as e:
        registry.dispose(source_id, "files", owner_id)
        raise SourceError(str(e))
    except SourceError:
        registry.dispose(source_id, "files", owner_id)
        raise
    except Exception as e:
        registry.dispose(source_id, "files", owner_id)
        raise SourceError(f"Could not load files: {clean_error(e)}")
    src = DataSource(id=source_id, owner_id=owner_id, name=name, engine="files",
                     config_encrypted=encrypt_config({"db_path": cfg["db_path"]}, source_id),
                     status="ok", schema_cache=schema,
                     schema_cached_at=datetime.now(timezone.utc))
    db.add(src)
    await db.commit()
    return src
