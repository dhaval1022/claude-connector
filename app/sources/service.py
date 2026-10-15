import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

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


async def create_source(db: AsyncSession, owner_id: int | str, name: str, engine: str,
                        cfg: dict) -> DataSource:
    name = name.strip()
    if not name or len(name) > 120:
        raise SourceError("Name is required (max 120 characters).")
    oid = int(owner_id)
    exists = (await db.execute(select(DataSource.id).where(
        DataSource.created_by == oid, DataSource.database_name == name,
        DataSource.deleted_at.is_(None)))).first()
    if exists:
        raise SourceError(f"You already have a data source named '{name}'.")
    try:
        if "host" in cfg:
            check_host(cfg["host"])
        conn = make_connector("test", engine, cfg)
        await conn.test()
        schema = await conn.introspect()
    except HostBlocked as e:
        raise SourceError(str(e))
    except Exception as e:  # driver errors: scrub credentials
        SqlConnector.dispose("test")
        raise SourceError(f"Connection failed: {clean_error(e, cfg)}")
    src = DataSource(database_name=name, engine=engine, config_encrypted=b"",
                     status="ok", schema_cache=schema, created_by=oid)
    db.add(src)
    await db.flush()
    src.config_encrypted = encrypt_config(cfg, str(src.id))
    await db.commit()
    return src


async def get_owned(db: AsyncSession, owner_id: int | str, source_id: int | str) -> DataSource | None:
    """The only way tools/UI load a source: always scoped to the owner."""
    try:
        sid, oid = int(source_id), int(owner_id)
    except (ValueError, TypeError):
        return None
    return (await db.execute(select(DataSource).where(
        DataSource.id == sid, DataSource.created_by == oid,
        DataSource.deleted_at.is_(None)))).scalar_one_or_none()


def connector_for(src: DataSource):
    cfg = decrypt_config(src.config_encrypted, str(src.id))
    if src.engine == "files":
        cfg["schema"] = src.schema_cache  # files are immutable: the cache is the schema
        db_path = Path(cfg["db_path"])
        if not db_path.exists() and cfg.get("s3_db_key"):
            from app.sources.s3 import download_file_from_s3_sync
            download_file_from_s3_sync(cfg["s3_db_key"], db_path)
    return make_connector(str(src.id), src.engine, cfg)


async def refresh_schema(db: AsyncSession, src: DataSource) -> dict:
    conn = connector_for(src)
    try:
        schema = await conn.introspect()
    except Exception as e:
        src.status = "error"
        src.updated_at = datetime.now(timezone.utc)
        await db.commit()
        raise SourceError(f"Schema refresh failed: {clean_error(e, getattr(conn, 'cfg', None))}")
    src.schema_cache, src.updated_at, src.status = schema, datetime.now(timezone.utc), "ok"
    await db.commit()
    return schema


async def delete_source(db: AsyncSession, owner_id: int | str, source_id: int | str) -> bool:
    src = await get_owned(db, owner_id, source_id)
    if not src:
        return False
    now = datetime.now(timezone.utc)
    src.deleted_at = now
    src.deleted_by = int(owner_id)
    if src.engine == "files":
        try:
            cfg = decrypt_config(src.config_encrypted, str(src.id))
            if cfg.get("s3_prefix"):
                from app.sources.s3 import delete_s3_prefix
                await delete_s3_prefix(cfg["s3_prefix"])
        except Exception:
            pass
    registry.dispose(str(src.id), src.engine, str(owner_id))
    await db.commit()
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


async def create_file_source(db: AsyncSession, owner_id: int | str, name: str,
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
    oid = int(owner_id)
    if (await db.execute(select(DataSource.id).where(
            DataSource.created_by == oid, DataSource.database_name == name,
            DataSource.deleted_at.is_(None)))).first():
        raise SourceError(f"You already have a data source named '{name}'.")
    src = DataSource(database_name=name, engine="files", created_by=oid,
                     config_encrypted=b"", status="ok", schema_cache=None)
    db.add(src)
    await db.flush()
    source_id = str(src.id)
    folder = registry.source_dir(str(oid), source_id)
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

        from app.sources.s3 import is_s3_configured, upload_file_to_s3
        if is_s3_configured():
            s3_prefix = f"sources/{oid}/{source_id}/"
            for p in saved:
                await upload_file_to_s3(p, f"{s3_prefix}{p.name}")
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
            s3_db_key = f"{s3_prefix}data.duckdb"
            await upload_file_to_s3(folder / "data.duckdb", s3_db_key)
            cfg["s3_bucket"] = s.aws_bucket_name
            cfg["s3_prefix"] = s3_prefix
            cfg["s3_db_key"] = s3_db_key
    except FileLoadError as e:
        registry.dispose(source_id, "files", str(oid))
        await db.rollback()
        raise SourceError(str(e))
    except SourceError:
        registry.dispose(source_id, "files", str(oid))
        await db.rollback()
        raise
    except Exception as e:
        registry.dispose(source_id, "files", str(oid))
        await db.rollback()
        raise SourceError(f"Could not load files: {clean_error(e)}")
    src.schema_cache = schema
    stored_cfg = {"db_path": cfg["db_path"]}
    if "s3_bucket" in cfg:
        stored_cfg.update({
            "s3_bucket": cfg["s3_bucket"],
            "s3_prefix": cfg["s3_prefix"],
            "s3_db_key": cfg["s3_db_key"],
        })
    src.config_encrypted = encrypt_config(stored_cfg, source_id)
    await db.commit()
    return src
