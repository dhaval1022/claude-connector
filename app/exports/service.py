"""CSV exports of FULL query results (not capped at the tool row limit).

Exactness: values are written as text exactly as the connector returns them (decimals as exact
strings, ISO dates, '' for NULL). The manifest records column types, row count and a SHA-256 so
any consumer (including generated analysis scripts) can verify it holds the complete,
unmodified result. An export that would exceed the row cap FAILS rather than truncating."""
import asyncio
import csv
import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from sqlalchemy import select

from app.auth.tokens import aware
from app.config import get_settings
from app.connectors.sql import _jsonable
from app.db.models import Export
from app.db.session import SessionLocal

_LOCKS: dict[str, asyncio.Lock] = {}


class ExportError(ValueError):
    """Safe-to-display export failure."""


def export_dir(owner_id: str) -> Path:
    return Path(get_settings().data_dir).resolve() / "exports" / owner_id


def _cell(v) -> str:
    v = _jsonable(v)
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _final_type(types: set[str]) -> str:
    """One type per column, widened over ALL values (not just the first non-null one)."""
    if not types:
        return "unknown"
    if len(types) == 1:
        return {"Decimal": "decimal"}.get(next(iter(types)), next(iter(types)))
    if types <= {"int", "float", "Decimal"}:
        return "decimal" if "Decimal" in types else "float"
    if types <= {"datetime", "date"}:
        return "datetime"
    return "str"   # genuinely mixed: treat as text


def write_csv(stream, path: Path, max_rows: int) -> tuple[list[dict], int]:
    """Consume a connector stream into `path`. Blocking. Returns (columns, row_count)."""
    gen = stream
    names, declared, seen = None, None, []   # seen[i] = set of python type names in column i
    rows = 0
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            for chunk in gen:
                if "columns" in chunk:
                    names, declared = chunk["columns"], chunk["types"]
                    seen = [set() for _ in names]
                    w.writerow(names)
                    continue
                for r in chunk["rows"]:
                    rows += 1
                    if rows > max_rows:
                        raise ExportError(
                            f"The result has more than {max_rows:,} rows, which exceeds the "
                            "export limit. Add filters or aggregate, then export again.")
                    for i, v in enumerate(r):
                        if v is not None:
                            seen[i].add(type(v).__name__)
                    w.writerow([_cell(v) for v in r])
    finally:
        gen.close()   # releases the DB connection even when we stop early
    if names is None:
        raise ExportError("The query returned no column information.")
    cols = [{"name": n, "type": (declared[i] if declared else _final_type(seen[i]))}
            for i, n in enumerate(names)]
    return cols, rows


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sign_link(export: Export, ttl_s: int | None = None) -> tuple[str, datetime]:
    s = get_settings()
    exp_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_s or s.export_link_ttl_s)
    token = jwt.encode({"sub": export.id, "uid": export.owner_id, "aud": "download",
                        "exp": int(exp_at.timestamp())}, s.jwt_secret, algorithm="HS256")
    return f"{s.public_base_url.rstrip('/')}/files/{token}", exp_at


def verify_link(token: str) -> dict | None:
    try:
        return jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"],
                          audience="download")
    except jwt.PyJWTError:
        return None


async def create_export(conn, sql_to_run: str, owner_id: str, source_id: str,
                        original_sql: str) -> Export:
    """`sql_to_run` must already be validated by the guard."""
    s = get_settings()
    lock = _LOCKS.setdefault(owner_id, asyncio.Lock())
    if lock.locked():
        raise ExportError("You already have an export running. Wait for it to finish.")
    async with lock:
        folder = export_dir(owner_id)
        folder.mkdir(parents=True, exist_ok=True)
        export = Export(id=uuid.uuid4().hex, owner_id=owner_id, source_id=source_id, sql_text=original_sql,
                        filename="", path="", rows=0, size_bytes=0, sha256="", columns=[],
                        expires_at=datetime.now(timezone.utc) + timedelta(hours=s.export_retention_h))
        path = folder / f"{export.id}.csv"
        t0 = time.monotonic()
        try:
            cols, rows = await asyncio.to_thread(
                lambda: write_csv(conn.stream(sql_to_run, s.export_timeout_s), path,
                                  s.export_max_rows))
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        export.filename = f"export_{export.id[:8]}.csv"
        export.path, export.rows, export.columns = str(path), rows, cols
        export.size_bytes, export.sha256 = path.stat().st_size, _sha256(path)
        if export.size_bytes > s.export_max_mb * 1024 * 1024:
            path.unlink(missing_ok=True)
            raise ExportError(f"The export is larger than {s.export_max_mb} MB. "
                              "Add filters or select fewer columns.")
        async with SessionLocal() as db:
            db.add(export)
            await db.commit()
        export.elapsed_ms = int((time.monotonic() - t0) * 1000)   # transient, for the response
        return export


async def get_owned_export(owner_id: str, export_id: str) -> Export | None:
    async with SessionLocal() as db:
        e = (await db.execute(select(Export).where(
            Export.id == export_id, Export.owner_id == owner_id))).scalar_one_or_none()
    if e and aware(e.expires_at) < datetime.now(timezone.utc):
        return None
    return e


def manifest(e: Export, with_link: bool = True) -> dict:
    out = {"export_id": e.id, "filename": e.filename, "rows": e.rows, "size_bytes": e.size_bytes,
           "sha256": e.sha256, "columns": e.columns, "sql": e.sql_text,
           "created_at": e.created_at.isoformat() if e.created_at else None,
           "file_expires_at": e.expires_at.isoformat()}
    if with_link:
        url, exp_at = sign_link(e)
        out.update(download_url=url, download_link_expires_at=exp_at.isoformat())
    return out


async def purge_expired() -> int:
    """Delete expired export files + rows. Safe to call repeatedly."""
    now, n = datetime.now(timezone.utc), 0
    async with SessionLocal() as db:
        for e in (await db.execute(select(Export).where(Export.expires_at < now))).scalars():
            Path(e.path).unlink(missing_ok=True)
            await db.delete(e)
            n += 1
        await db.commit()
    return n
