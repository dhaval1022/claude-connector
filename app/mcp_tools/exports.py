"""Export tools: get a COMPLETE query result out as a verified CSV for analysis scripts."""
from sqlalchemy import select

from app import breaker
from app.audit.logger import audit
from app.config import get_settings
from app.db.models import Export
from app.db.session import SessionLocal
from app.exports import service as exports
from app.guard.sql_validator import QueryRejected
from app.mcp_tools.data import _load, validated_query
from app.mcp_tools.server import app_enabled_for_user, current_user_id, mcp
from app.ratelimit import enforce
from app.sources.service import clean_error, connector_for


@mcp.tool()
async def export_result(source_id: str, sql: str) -> dict:
    """Export the FULL result of a read-only SELECT to a CSV file for use in an analysis script.

    Use this (instead of run_query) when the result is too large for run_query's row cap or a
    Python script needs the raw rows. Same safety rules as run_query. The response is a
    manifest: row count, byte size, SHA-256, column names/types and a short-lived download_url.
    The export FAILS (it never truncates) if the result exceeds the export row limit, so a
    successful export is always complete. Files are deleted after about a day; call
    get_export_link for a fresh link. Then use generate_analysis_script to get a script."""
    src = await _load(source_id)
    s = get_settings()
    conn = connector_for(src)
    uid = current_user_id.get()
    try:
        enforce("exports", uid, s.rate_exports_per_hour, 3600)
        breaker.check(src.id)
        v = validated_query(src, conn.dialect, sql, s.export_max_rows)
        e = await exports.create_export(conn, v.sql, uid, src.id, sql)
        breaker.record_success(src.id)
    except (QueryRejected, exports.ExportError, ValueError) as err:
        await audit(user_id=uid, tool="export_result", source_id=src.id, sql=sql,
                    status="rejected", error=str(err))
        raise ValueError(str(err))
    except Exception as err:
        breaker.record_failure(src.id, err)
        msg = clean_error(err, getattr(conn, "cfg", None))
        await audit(user_id=uid, tool="export_result", source_id=src.id, sql=sql,
                    status="error", error=msg)
        raise ValueError(f"Export failed: {msg}")
    await audit(user_id=uid, tool="export_result", source_id=src.id, sql=sql, status="ok",
                row_count=e.rows, elapsed_ms=getattr(e, "elapsed_ms", None))
    m = exports.manifest(e)
    m["note"] = ("Complete result (not truncated). Values are exact text: decimals unrounded, "
                 "codes with leading zeros intact. Read text/id columns as strings in pandas "
                 "(dtype=str) to preserve them.")
    return m


@mcp.tool()
async def get_export_link(export_id: str) -> dict:
    """Get a fresh short-lived download link for one of your exports (links expire in ~30
    minutes; the file itself is kept about a day)."""
    e = await exports.get_owned_export(current_user_id.get(), export_id)
    if not e:
        raise ValueError("Export not found or expired. Run export_result again.")
    await _load(e.source_id)            # the export's data source must be enabled for this app
    return exports.manifest(e)


@mcp.tool()
async def list_exports(limit: int = 20) -> dict:
    """List your recent, still-available exports (newest first), without download links."""
    if not await app_enabled_for_user():      # the user has not enabled THIS app
        return {"exports": []}
    async with SessionLocal() as db:
        rows = (await db.execute(select(Export).where(Export.owner_id == current_user_id.get())
                                 .order_by(Export.created_at.desc())
                                 .limit(min(max(limit, 1), 100)))).scalars().all()
    return {"exports": [exports.manifest(e, with_link=False) for e in rows
                        if e.expires_at is not None]}
