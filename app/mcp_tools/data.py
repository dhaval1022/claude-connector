"""Discovery + query tools. Every tool resolves the source through get_owned(), so a user can
only ever reach their own data sources."""
import difflib
import re
from datetime import datetime, timezone

from sqlglot import exp

from app import breaker
from app.audit.logger import audit
from app.config import get_settings
from app.db.models import DataSource
from app.db.session import SessionLocal
from app.guard.sql_validator import QueryRejected, validate
from app.mcp_tools.server import current_user_id, mcp
from app.ratelimit import enforce
from app.semantic import service as semantic
from app.sources.service import (SourceError, clean_error, connector_for, find_table,
                                 flat_tables, get_owned, refresh_schema)

NOT_FOUND = "Data source not found. Call list_data_sources to see valid ids."


async def _load(source_id: str) -> DataSource:
    enforce("tools", current_user_id.get(), get_settings().rate_tools_per_min, 60)
    async with SessionLocal() as db:
        src = await get_owned(db, current_user_id.get(), source_id)
    if not src:
        raise ValueError(NOT_FOUND)
    return src


def _ensure_schema(src: DataSource) -> dict:
    if not src.schema_cache:
        raise ValueError("Schema not loaded yet. Call refresh_schema first.")
    return src.schema_cache


def _schema_columns(cache: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for _, t, info in flat_tables(cache):
        out.setdefault(t.lower(), set()).update(c["name"].lower() for c in info["columns"])
    return out


def _check_tables_exist(cache: dict | None, tables: list[tuple[str | None, str]]) -> None:
    """Schema grounding: unknown tables get 'did you mean' help instead of a DB error."""
    if not cache:
        return
    known = [f"{s}.{t}" for s, t, _ in flat_tables(cache)]
    for schema, table in tables:
        if schema and schema.lower() in ("information_schema", "sys"):
            continue
        ref = f"{schema}.{table}" if schema else table
        if not find_table(cache, ref):
            close = difflib.get_close_matches(ref, known + [k.split(".", 1)[1] for k in known],
                                              n=5, cutoff=0.5)
            hint = f" Did you mean: {', '.join(dict.fromkeys(close))}?" if close else ""
            raise ValueError(f"Table '{ref}' was not found in this data source.{hint} "
                             "Use search_schema or get_schema_overview to find the right name.")


def _mentions(sql: str, name: str) -> bool:
    """True if `name` appears as a whole identifier in the SQL (case-insensitive)."""
    return re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", sql,
                     re.IGNORECASE) is not None


def validated_query(src: DataSource, dialect: str, sql: str, cap: int):
    """The one place a user's SQL is checked: read-only guard, masking, schema grounding."""
    cache = src.schema_cache
    masked = {m.lower() for m in (src.masked_columns or [])}
    # Unknown tables first, so a typo gets "did you mean" rather than a masking error.
    _check_tables_exist(cache, validate(sql, dialect).tables)
    return validate(sql, dialect, max_rows=cap, masked_columns=masked,
                    schema_columns=_schema_columns(cache) if cache else None)


async def _run(src: DataSource, sql: str, max_rows: int | None, tool: str) -> dict:
    s = get_settings()
    cap = min(max(int(max_rows or s.default_max_rows), 1), s.hard_max_rows)
    conn = connector_for(src)
    uid = current_user_id.get()
    try:
        enforce("queries", uid, s.rate_queries_per_min, 60)
        breaker.check(src.id)
        v = validated_query(src, conn.dialect, sql, cap)
        res = await conn.execute(v.sql, cap, s.query_timeout_s)
        breaker.record_success(src.id)
    except (QueryRejected, ValueError) as e:
        await audit(user_id=uid, tool=tool, source_id=src.id, sql=sql, status="rejected",
                    error=str(e))
        raise ValueError(str(e))
    except Exception as e:
        breaker.record_failure(src.id, e)
        msg = clean_error(e, getattr(conn, "cfg", None))  # never leak credentials
        await audit(user_id=uid, tool=tool, source_id=src.id, sql=sql, status="error",
                    error=msg)
        raise ValueError(f"Database error: {msg}")
    await audit(user_id=uid, tool=tool, source_id=src.id, sql=sql, status="ok",
                row_count=res["row_count"], elapsed_ms=res["elapsed_ms"])
    warnings = []
    if res["truncated"]:
        warnings.append(
            f"RESULT TRUNCATED at {cap} rows; more rows exist. Do not treat these rows as the "
            "full result. Aggregate in SQL (GROUP BY / COUNT / SUM), add filters, or raise "
            f"max_rows (hard limit {s.hard_max_rows}).")
    for sch, tbl in v.tables:  # partitioned tables queried without a partition filter
        ref = f"{sch}.{tbl}" if sch else tbl
        found = find_table(src.schema_cache, ref) if src.schema_cache else None
        keys = (found[2].get("partition_keys") if found else None) or []
        if keys and not any(_mentions(sql, k) for k in keys):
            warnings.append(
                f"Table '{tbl}' is partitioned by {', '.join(keys)} but the query does not "
                "filter on any partition column, so it may scan the entire table (cost and "
                "time). Add a partition filter unless a full scan is intended.")
    return {"source": {"id": src.id, "name": src.name, "engine": src.engine},
            "dialect": conn.dialect, "executed_sql": v.sql, **res, "max_rows": cap,
            "as_of": datetime.now(timezone.utc).isoformat(), "warnings": warnings}


@mcp.tool()
async def get_schema_overview(source_id: str, schema: str | None = None, offset: int = 0,
                              limit: int = 100) -> dict:
    """List the tables and views of a data source (names, kind, column counts).

    Call this after list_data_sources to learn what exists. Never guess table or column
    names; use this, search_schema and describe_table. Paginated with offset/limit."""
    src = await _load(source_id)
    cache = _ensure_schema(src)
    rows = [(s, t, i) for s, t, i in flat_tables(cache)
            if not schema or s.lower() == schema.lower()]
    page = rows[max(offset, 0): max(offset, 0) + min(max(limit, 1), 500)]
    return {"source": src.name, "engine": src.engine,
            "default_schema": cache.get("default_schema"),
            "schemas": sorted(cache.get("schemas", {})), "total_tables": len(rows),
            "offset": offset,
            "tables": [{"schema": s, "table": t, "kind": i["kind"],
                        "columns": len(i["columns"]),
                        **({"rows": i["rows"]} if "rows" in i else {})}
                       for s, t, i in page],
            "schema_cached_at": src.schema_cached_at.isoformat()
            if src.schema_cached_at else None}


@mcp.tool()
async def search_schema(source_id: str, query: str) -> dict:
    """Find tables and columns by keyword (case-insensitive, partial words allowed).

    Use when you do not know the exact table/column names, e.g. query='invoice' or 'mrp'."""
    src = await _load(source_id)
    cache = _ensure_schema(src)
    words = [w for w in query.lower().replace(",", " ").split() if w]
    if not words:
        raise ValueError("Provide a search keyword.")
    hits = []
    for s, t, info in flat_tables(cache):
        score = sum(3 for w in words if w in t.lower())
        cols = [c["name"] for c in info["columns"] if any(w in c["name"].lower() for w in words)]
        score += len(cols)
        if score:
            hits.append((score, {"schema": s, "table": t, "matching_columns": cols[:15]}))
    hits.sort(key=lambda h: -h[0])
    terms = await semantic.matching_terms(current_user_id.get(), src.id, words)
    return {"query": query, "matches": [h[1] for h in hits[:25]], "total_matches": len(hits),
            **({"business_terms": terms} if terms else {})}


@mcp.tool()
async def describe_table(source_id: str, table: str, sample_rows: int = 3) -> dict:
    """Columns (name, type, nullable), primary key, foreign keys and a few sample rows.

    `table` may be 'name' or 'schema.name'. Always call this before writing SQL against a
    table. Columns marked masked cannot be queried."""
    src = await _load(source_id)
    cache = _ensure_schema(src)
    found = find_table(cache, table)
    if not found:
        _check_tables_exist(cache, [(None, table)])
    schema, name, info = found
    masked = {m.lower() for m in (src.masked_columns or [])}
    cols = [{**c, "masked": c["name"].lower() in masked} for c in info["columns"]]
    sample, note = None, None
    visible = [c["name"] for c in cols if not c["masked"]]
    n = min(max(sample_rows, 0), 10)
    if n and visible:
        q = (exp.select(*[exp.column(c, quoted=True) for c in visible])
             .from_(exp.table_(name, db=schema, quoted=True)).limit(n))
        try:
            sample = await _run(src, q.sql(dialect=connector_for(src).dialect), n, "describe_table")
            sample = {"columns": [c["name"] for c in sample["columns"]], "rows": sample["rows"]}
        except ValueError as e:
            note = f"Sample rows unavailable: {e}"
    notes = await semantic.notes_for_table(current_user_id.get(), src.id, name)
    if notes.get("columns"):
        for c in cols:
            n = notes["columns"].get(c["name"]) or notes["columns"].get(c["name"].lower())
            if n:
                c["business_note"] = n
    return {"schema": schema, "table": name, "kind": info["kind"], "columns": cols,
            **({"business_note": notes["table"]} if notes.get("table") else {}),
            "primary_key": info["primary_key"], "foreign_keys": info["foreign_keys"],
            "sample": sample, "note": note,
            **({"row_count": info["rows"]} if "rows" in info else {}),
            **({"source_file": info["source_file"]} if info.get("source_file") else {}),
            **({"data_notes": info["notes"]} if info.get("notes") else {})}


@mcp.tool()
async def run_query(source_id: str, sql: str, max_rows: int = 500) -> dict:
    """Run ONE read-only SELECT (or WITH ... SELECT) in the data source's own SQL dialect.

    Only SELECT is allowed; anything else is rejected. The response includes columns, rows,
    row_count, `truncated` (true means MORE rows exist than returned), executed_sql and
    warnings. Prefer aggregating in SQL over pulling raw rows. Numbers are exact (decimals
    come back as strings). Check table/column names with describe_table first."""
    src = await _load(source_id)
    return await _run(src, sql, max_rows, "run_query")


@mcp.tool()
async def refresh_schema_cache(source_id: str) -> dict:
    """Re-read the database's tables/columns. Use after the database structure changed or
    when a table you expect is missing."""
    async with SessionLocal() as db:
        src = await get_owned(db, current_user_id.get(), source_id)
        if not src:
            raise ValueError(NOT_FOUND)
        try:
            cache = await refresh_schema(db, src)
        except SourceError as e:
            raise ValueError(str(e))
    return {"source": src.name, "tables": len(flat_tables(cache)),
            "schema_cached_at": src.schema_cached_at.isoformat()}
