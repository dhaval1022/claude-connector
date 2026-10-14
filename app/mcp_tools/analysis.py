"""Data-quality and analysis tools. Queries are built with sqlglot (correct quoting/dialect),
executed through the same guarded path as run_query, and all arithmetic on results uses Decimal
so reported numbers are exact."""
import re
import statistics
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

import sqlglot
from sqlglot import exp

from app.guard.sql_validator import validate
from app.mcp_tools.data import _ensure_schema, _load, _run
from app.mcp_tools.server import mcp
from app.mcp_tools.sqlkit import (col, col_kind, count_star, date_literal, day_expr,
                                  find_column, lookup, require_column, table_expr)
from app.sources.service import connector_for, flat_tables

GENERIC_NAMES = {"id", "name", "type", "status", "description", "created_at", "updated_at",
                 "created_on", "updated_on", "date", "code", "remarks", "notes", "created_by",
                 "updated_by", "is_active", "active", "deleted", "comment", "comments"}
STALE_DAYS = 45
AGGS = {"SUM": exp.Sum, "AVG": exp.Avg, "MIN": exp.Min, "MAX": exp.Max, "COUNT": exp.Count}


def _dec(v) -> Decimal | None:
    if v is None:
        return None
    try:
        return Decimal(str(v))
    except InvalidOperation:
        return None


def _fmt(d: Decimal | None) -> str | None:
    return None if d is None else format(d, "f")


def _pct(part: Decimal, whole: Decimal) -> float:
    return float(round(part * 100 / whole, 2)) if whole else 0.0


def _alias(e, name):
    return exp.alias_(e, name)


async def _ctx(source_id: str, table: str):
    src = await _load(source_id)
    cache = _ensure_schema(src)
    schema, name, info = lookup(cache, table)
    return src, cache, schema, name, info, connector_for(src).dialect


async def _go(src, dialect, query: exp.Expression, tool: str, max_rows: int = 1000) -> dict:
    return await _run(src, query.sql(dialect=dialect), max_rows, tool)


_DATEISH_NAME = re.compile(r"(date|time|day|_on|_at|_dt|^dt)$|^(date|dt)", re.I)


def _is_date_like(name: str, kind: str) -> bool:
    """Real date columns, plus text columns that are named like dates (ISO strings)."""
    return kind in ("date", "timestamp") or (kind == "text" and bool(_DATEISH_NAME.search(name)))


def _stale_warning(label: str, latest) -> str | None:
    try:
        d = date.fromisoformat(str(latest)[:10])
    except (TypeError, ValueError):
        return None
    age = (datetime.now(timezone.utc).date() - d).days
    if age > STALE_DAYS:
        return f"{label}: latest value is {d} ({age} days ago); the data may be stale."
    return None


# ------------------------------------------------------------------ profiling
@mcp.tool()
async def profile_column(source_id: str, table: str, column: str, top_n: int = 10) -> dict:
    """Profile one column: row count, nulls, distinct count, min/max (and avg, negatives,
    zeros for numbers), top values, plus data-quality warnings (all-null, constant, stale
    dates, negatives). Use before relying on a column. Runs full-column aggregate queries."""
    src, _, schema, name, info, dialect = await _ctx(source_id, table)
    c = require_column(info, name, column)
    kind, x = col_kind(c["type"]), col(c["name"])
    sels = [_alias(count_star(), "total"), _alias(exp.Count(this=x), "non_null"),
            _alias(exp.Count(this=exp.Distinct(expressions=[x])), "distinct_count")]
    if kind != "other":
        sels += [_alias(exp.Min(this=x), "min_v"), _alias(exp.Max(this=x), "max_v")]
    if kind == "numeric":
        sels += [_alias(exp.Avg(this=x), "avg_v"),
                 _alias(exp.Sum(this=exp.case().when(x < 0, 1).else_(0)), "negatives"),
                 _alias(exp.Sum(this=exp.case().when(exp.EQ(this=x, expression=exp.Literal.number(0)), 1).else_(0)), "zeros")]
    r = await _go(src, dialect, exp.select(*sels).from_(table_expr(schema, name)),
                  "profile_column", 1)
    row = dict(zip([k["name"] for k in r["columns"]], r["rows"][0]))
    total, non_null = int(row["total"]), int(row["non_null"])
    nulls = total - non_null
    out = {"table": name, "column": c["name"], "type": c["type"], "total_rows": total,
           "non_null": non_null, "null_count": nulls,
           "null_pct": _pct(Decimal(nulls), Decimal(total)),
           "distinct_count": int(row["distinct_count"]),
           "min": row.get("min_v"), "max": row.get("max_v")}
    warnings = list(r["warnings"])
    if kind == "numeric":
        out.update(avg=row["avg_v"], negatives=int(row["negatives"] or 0),
                   zeros=int(row["zeros"] or 0))
        if out["negatives"]:
            warnings.append(f"{out['negatives']} negative values (returns/adjustments or errors?).")
    if total == 0:
        warnings.append("The table is empty.")
    elif non_null == 0:
        warnings.append("Every value is NULL; this column carries no data.")
    elif out["null_pct"] > 50:
        warnings.append(f"{out['null_pct']}% of values are NULL.")
    if non_null and out["distinct_count"] == 1:
        warnings.append("Constant column: only one distinct value.")
    if _is_date_like(c["name"], kind) and out["max"]:
        w = _stale_warning(c["name"], out["max"])
        if w:
            warnings.append(w)
    n = min(max(top_n, 0), 50)
    if n and non_null:
        top = (exp.select(x, _alias(count_star(), "n")).from_(table_expr(schema, name))
               .group_by(x).order_by(exp.Ordered(this=exp.column("n"), desc=True),
                                     exp.Ordered(this=x)).limit(n))
        t = await _go(src, dialect, top, "profile_column", n)
        out["top_values"] = [{"value": v, "count": int(cnt),
                              "pct": _pct(Decimal(int(cnt)), Decimal(total))}
                             for v, cnt in t["rows"]]
    out["warnings"] = warnings
    return out


@mcp.tool()
async def profile_table(source_id: str, table: str) -> dict:
    """Profile a whole table in one pass: exact row count, per-column null %, date ranges,
    primary-key uniqueness, and warnings (empty columns, mostly-NULL columns, stale dates,
    duplicate primary keys). Masked columns are skipped. Up to 60 columns are profiled."""
    src, _, schema, name, info, dialect = await _ctx(source_id, table)
    masked = {m.lower() for m in (src.masked_columns or [])}
    cols = [c for c in info["columns"] if c["name"].lower() not in masked]
    notes = []
    if len(cols) > 60:
        notes.append(f"Table has {len(cols)} columns; only the first 60 were profiled.")
        cols = cols[:60]
    sels = [_alias(count_star(), "total")]
    for i, c in enumerate(cols):
        sels.append(_alias(exp.Count(this=col(c["name"])), f"n{i}"))
        if _is_date_like(c["name"], col_kind(c["type"])):
            sels += [_alias(exp.Min(this=col(c["name"])), f"lo{i}"),
                     _alias(exp.Max(this=col(c["name"])), f"hi{i}")]
    r = await _go(src, dialect, exp.select(*sels).from_(table_expr(schema, name)),
                  "profile_table", 1)
    row = dict(zip([k["name"] for k in r["columns"]], r["rows"][0]))
    total = int(row["total"])
    warnings, columns = list(r["warnings"]), []
    for i, c in enumerate(cols):
        nn = int(row[f"n{i}"])
        entry = {"name": c["name"], "type": c["type"], "non_null": nn,
                 "null_pct": _pct(Decimal(total - nn), Decimal(total))}
        if f"lo{i}" in row:
            entry["min"], entry["max"] = row[f"lo{i}"], row[f"hi{i}"]
            w = _stale_warning(c["name"], entry["max"])
            if w:
                warnings.append(w)
        if total and nn == 0:
            warnings.append(f"Column '{c['name']}' is entirely NULL.")
        elif total and entry["null_pct"] > 50:
            warnings.append(f"Column '{c['name']}' is {entry['null_pct']}% NULL.")
        columns.append(entry)
    pk = info.get("primary_key") or []
    pk_check = None
    if len(pk) == 1 and total:
        d = await _go(src, dialect, exp.select(_alias(
            exp.Count(this=exp.Distinct(expressions=[col(pk[0])])), "d"))
            .from_(table_expr(schema, name)), "profile_table", 1)
        distinct = int(d["rows"][0][0])
        pk_check = {"column": pk[0], "rows": total, "distinct": distinct,
                    "unique": distinct == total}
        if distinct != total:
            warnings.append(f"Primary key '{pk[0]}' has {total - distinct} duplicate rows.")
    if total == 0:
        warnings.append("The table is empty.")
    return {"table": name, "schema": schema, "row_count": total, "columns": columns,
            "primary_key_check": pk_check, "notes": notes, "warnings": warnings,
            "as_of": r["as_of"]}


# ------------------------------------------------------------------ validation
def _wrap(sql: str, dialect: str) -> exp.Subquery:
    validate(sql, dialect)   # raises QueryRejected (a ValueError) if not a read-only SELECT
    tree = sqlglot.parse_one(sql, read=dialect)
    if isinstance(tree, exp.Select) and tree.args.get("order") and not tree.args.get("limit"):
        tree.set("order", None)   # ORDER BY is invalid (and irrelevant) inside a subquery
    return tree.subquery("_q")


@mcp.tool()
async def validate_result(source_id: str, sql: str, checks: list[str] | None = None,
                          key_columns: list[str] | None = None,
                          sum_columns: list[str] | None = None,
                          null_columns: list[str] | None = None) -> dict:
    """Reconcile a query's FULL result (not just the rows you were shown) before reporting.

    checks (default ["row_count"]):
      row_count       exact number of rows the query returns
      duplicate_keys  needs key_columns; finds repeated keys. Run it after JOINs with the key
                      of the entity you are counting: duplicates mean join fan-out that
                      inflates SUM/COUNT.
      null_counts     needs null_columns; NULLs per column
      sums            needs sum_columns; exact SUM over the full result, to compare with
                      totals computed from a truncated sample."""
    src = await _load(source_id)
    dialect = connector_for(src).dialect
    inner = _wrap(sql, dialect)
    wanted = checks or ["row_count"]
    unknown = [c for c in wanted if c not in ("row_count", "duplicate_keys", "null_counts", "sums")]
    if unknown:
        raise ValueError(f"Unknown checks: {unknown}")
    result: dict = {}

    async def run(q, mr=50):
        return await _go(src, dialect, q, "validate_result", mr)

    if "row_count" in wanted:
        r = await run(exp.select(_alias(count_star(), "n")).from_(inner), 1)
        result["row_count"] = {"status": "info", "rows": int(r["rows"][0][0])}
    if "duplicate_keys" in wanted:
        if not key_columns:
            raise ValueError("duplicate_keys requires key_columns.")
        keys = [col(k) for k in key_columns]
        g = exp.select(*keys, _alias(count_star(), "c")).from_(inner).group_by(*keys)
        stats = (exp.select(_alias(count_star(), "distinct_keys"),
                            _alias(exp.Sum(this=exp.column("c")), "total_rows"),
                            _alias(exp.Sum(this=exp.case().when(exp.column("c") > 1, 1).else_(0)),
                                   "duplicated_keys"),
                            _alias(exp.Max(this=exp.column("c")), "max_repeat"))
                 .from_(g.subquery("g")))
        s = (await run(stats, 1))["rows"][0]
        distinct, total, dup, mx = int(s[0]), int(s[1] or 0), int(s[2] or 0), int(s[3] or 0)
        entry = {"status": "pass" if dup == 0 else "fail", "key_columns": key_columns,
                 "rows": total, "distinct_keys": distinct, "duplicated_keys": dup,
                 "max_rows_per_key": mx,
                 "fan_out_factor": float(round(Decimal(total) / Decimal(distinct), 4))
                 if distinct else None}
        if dup:
            ex = (exp.select(*keys, exp.column("c")).from_(g.subquery("g"))
                  .where(exp.column("c") > 1)
                  .order_by(exp.Ordered(this=exp.column("c"), desc=True)).limit(10))
            entry["examples"] = (await run(ex, 10))["rows"]
            entry["explanation"] = ("Keys repeat, so rows are duplicated (likely a JOIN fan-out). "
                                    "SUM/COUNT over this result will be inflated.")
        result["duplicate_keys"] = entry
    if "null_counts" in wanted:
        if not null_columns:
            raise ValueError("null_counts requires null_columns.")
        sels = [_alias(count_star(), "total")] + [
            _alias(exp.Count(this=col(c)), f"n{i}") for i, c in enumerate(null_columns)]
        row = (await run(exp.select(*sels).from_(inner), 1))["rows"][0]
        total = int(row[0])
        result["null_counts"] = {"status": "info", "rows": total, "columns": {
            c: {"nulls": total - int(row[i + 1]),
                "null_pct": _pct(Decimal(total - int(row[i + 1])), Decimal(total))}
            for i, c in enumerate(null_columns)}}
    if "sums" in wanted:
        if not sum_columns:
            raise ValueError("sums requires sum_columns.")
        sels = [_alias(count_star(), "total")] + [
            _alias(exp.Sum(this=col(c)), f"s{i}") for i, c in enumerate(sum_columns)]
        row = (await run(exp.select(*sels).from_(inner), 1))["rows"][0]
        result["sums"] = {"status": "info", "rows": int(row[0]),
                          "sums": {c: row[i + 1] for i, c in enumerate(sum_columns)}}
    failed = [k for k, v in result.items() if v["status"] == "fail"]
    return {"checks": result, "all_passed": not failed, "failed": failed}


# ------------------------------------------------------------------ relationships
def _infer(a_name, a_info, b_name, b_info):
    """Candidate joins a.col -> b.col, strongest reason first."""
    out = []
    b_pk = b_info.get("primary_key") or []
    stem = b_name.lower().rstrip("s")
    fk_cols = {c.lower() for f in a_info.get("foreign_keys", []) for c in f["columns"]}
    for ac in a_info["columns"]:
        an = ac["name"].lower()
        if an in fk_cols:
            continue
        ak = col_kind(ac["type"])
        if len(b_pk) == 1:
            bc = find_column(b_info, b_pk[0])
            if bc and an == b_pk[0].lower() and an != "id" and col_kind(bc["type"]) == ak:
                out.append((1, ac["name"], bc["name"], "same name as the other table's primary key"))
                continue
            if bc and an in (f"{b_name.lower()}_id", f"{stem}_id", f"{stem}id") \
                    and col_kind(bc["type"]) == ak:
                out.append((2, ac["name"], bc["name"], "foreign-key naming pattern"))
                continue
        bc = find_column(b_info, ac["name"])
        if bc and an not in GENERIC_NAMES and ak == col_kind(bc["type"]) and ak != "other":
            out.append((3, ac["name"], bc["name"], "same column name and type"))
    return out


@mcp.tool()
async def get_relationships(source_id: str, table: str, verify: bool = True) -> dict:
    """How a table joins to others: declared foreign keys (both directions) plus INFERRED
    joins from naming/type patterns. With verify=true each of the top inferred joins is tested
    against real data (sampled distinct values; match_rate = share found in the other table),
    so you only use joins that actually line up. Inferred joins are suggestions, not facts."""
    src, cache, schema, name, info, dialect = await _ctx(source_id, table)
    declared = [{"direction": "outbound", "columns": f["columns"],
                 "references": f"{f.get('ref_schema') or ''}.{f['ref_table']}".lstrip("."),
                 "ref_columns": f["ref_columns"]} for f in info.get("foreign_keys", [])]
    cands = []
    for osch, oname, oinfo in flat_tables(cache):
        if (osch, oname) == (schema, name):
            continue
        for fk in oinfo.get("foreign_keys", []):
            if fk["ref_table"].lower() == name.lower():
                declared.append({"direction": "inbound", "from": f"{osch}.{oname}",
                                 "columns": fk["columns"], "ref_columns": fk["ref_columns"]})
        for pri, a, b, why in _infer(name, info, oname, oinfo):
            cands.append((pri, "outbound", osch, oname, a, b, why))
        for pri, a, b, why in _infer(oname, oinfo, name, info):
            cands.append((pri, "inbound", osch, oname, b, a, why))   # b is this table's column
    cands.sort(key=lambda c: c[0])
    inferred = []
    for i, (pri, direction, osch, oname, mine, theirs, why) in enumerate(cands[:30]):
        item = {"direction": direction, "this_column": mine, "other_table": f"{osch}.{oname}",
                "other_column": theirs, "reason": why}
        if verify and i < 6:
            inner = (exp.select(col(mine).as_("v")).distinct().from_(table_expr(schema, name))
                     .where(exp.Not(this=exp.Is(this=col(mine), expression=exp.Null())))
                     .limit(10000))
            q = (exp.select(_alias(exp.Count(this=exp.Distinct(
                    expressions=[exp.column("v", table="s")])), "sampled"),
                    _alias(exp.Count(this=exp.Distinct(
                        expressions=[exp.column(theirs, table="o", quoted=True)])), "matched"))
                 .from_(inner.subquery("s"))
                 .join(exp.table_(oname, db=osch, alias="o", quoted=True),
                       on=exp.EQ(this=exp.column("v", table="s"),
                                 expression=exp.column(theirs, table="o", quoted=True)),
                       join_type="left"))
            try:
                r = await _go(src, dialect, q, "get_relationships", 1)
                sampled, matched = int(r["rows"][0][0]), int(r["rows"][0][1])
                rate = round(matched / sampled, 4) if sampled else 0.0
                item.update(sampled_distinct_values=sampled, match_rate=rate,
                            confidence="high" if rate >= 0.95 else "medium" if rate >= 0.7
                            else "low")
            except ValueError as e:
                item.update(confidence="unverified", verify_error=str(e)[:200])
        else:
            item["confidence"] = "unverified"
        inferred.append(item)
    inferred.sort(key=lambda x: -(x.get("match_rate") or -1))
    return {"table": f"{schema}.{name}", "declared": declared, "inferred": inferred,
            "note": "Inferred joins are heuristics; prefer high-confidence ones and confirm "
                    "row counts with validate_result(duplicate_keys) after joining."}


# ------------------------------------------------------------------ period comparison
def _agg(kind: str, measure: exp.Expression, cond: exp.Expression) -> exp.Expression:
    return AGGS[kind](this=exp.case().when(cond, measure))


def _where(extra: str | None, dialect: str, base: exp.Expression) -> exp.Expression:
    if not extra:
        return base
    try:
        return exp.and_(base, sqlglot.condition(extra, dialect=dialect))
    except sqlglot.errors.SqlglotError as e:
        raise ValueError(f"Could not parse the `where` filter: {str(e)[:200]}")


def _measure(info, table, measure, aggregation):
    agg = aggregation.upper()
    if agg not in AGGS:
        raise ValueError(f"aggregation must be one of {sorted(AGGS)}")
    if measure.strip() == "*":
        if agg != "COUNT":
            raise ValueError("measure '*' is only valid with COUNT.")
        return agg, exp.Literal.number(1)
    c = require_column(info, table, measure)
    if agg in ("SUM", "AVG") and col_kind(c["type"]) != "numeric":
        raise ValueError(f"Column '{c['name']}' is {c['type']}, not numeric; cannot {agg} it.")
    return agg, col(c["name"])


@mcp.tool()
async def compare_periods(source_id: str, table: str, date_column: str, measure: str,
                          baseline_start: str, baseline_end: str,
                          current_start: str, current_end: str,
                          aggregation: str = "SUM", group_by: str | None = None,
                          where: str | None = None, top_n: int = 20) -> dict:
    """Compare a measure between two periods, optionally by a dimension (e.g. category, store).

    Dates are ISO (YYYY-MM-DD) and each period is HALF-OPEN: start inclusive, end EXCLUSIVE
    (March = 2026-03-01 to 2026-04-01). Returns baseline, current, delta, % change and each
    group's contribution to the total change, sorted by impact. Totals are computed by a
    separate exact query and reconciled against the group sums. aggregation: SUM, AVG, MIN,
    MAX, COUNT (use measure='*' for row counts). `where` is an optional SQL predicate."""
    src, _, schema, name, info, dialect = await _ctx(source_id, table)
    dc = require_column(info, name, date_column)
    kind = col_kind(dc["type"])
    if kind not in ("date", "timestamp", "text"):
        raise ValueError(f"'{dc['name']}' ({dc['type']}) is not a date column.")
    bs, be, cs, ce = (date.fromisoformat(d) for d in
                      (baseline_start, baseline_end, current_start, current_end))
    if bs >= be or cs >= ce:
        raise ValueError("Each period's end must be after its start (end is exclusive).")
    agg, m = _measure(info, name, measure, aggregation)
    d = col(dc["name"])

    def period(s, e):
        return exp.and_(exp.GTE(this=d, expression=date_literal(s, kind)),
                        exp.LT(this=d, expression=date_literal(e, kind)))
    pb, pc = period(baseline_start, baseline_end), period(current_start, current_end)
    sels = [_alias(_agg(agg, m, pb), "baseline"), _alias(_agg(agg, m, pc), "current_v")]
    base_where = _where(where, dialect, exp.or_(pb, pc))   # also lets the DB prune partitions
    tot = await _go(src, dialect,
                    exp.select(*sels).from_(table_expr(schema, name)).where(base_where),
                    "compare_periods", 1)
    warnings = list(tot["warnings"])
    t_base, t_cur = _dec(tot["rows"][0][0]), _dec(tot["rows"][0][1])
    zero = Decimal(0) if agg in ("SUM", "COUNT") else None

    def row_out(label, b, c):
        b = b if b is not None else zero
        c = c if c is not None else zero
        delta = (c - b) if (b is not None and c is not None) else None
        pct = float(round(delta * 100 / b, 2)) if delta is not None and b else None
        return {"group": label, "baseline": _fmt(b), "current": _fmt(c),
                "delta": _fmt(delta), "pct_change": pct}, delta

    out = {"table": name, "measure": f"{agg}({measure})", "baseline": [baseline_start, baseline_end],
           "current": [current_start, current_end]}
    total_row, total_delta = row_out("TOTAL", t_base, t_cur)
    out["total"] = total_row
    bdays, cdays = (be - bs).days, (ce - cs).days
    if bdays != cdays:
        warnings.append(f"Periods differ in length ({bdays} vs {cdays} days); totals are not "
                        "like-for-like. Consider normalizing per day.")
    if t_base in (None, 0) and agg in ("SUM", "COUNT"):
        warnings.append("The baseline period has no data; % change is undefined.")
    if group_by:
        gc = require_column(info, name, group_by)
        g = col(gc["name"])
        q = (exp.select(g, *sels).from_(table_expr(schema, name)).where(base_where).group_by(g))
        r = await _go(src, dialect, q, "compare_periods", 10_000)
        warnings += [w for w in r["warnings"] if w not in warnings]
        rows = []
        for key, b, c in r["rows"]:
            item, delta = row_out(key, _dec(b), _dec(c))
            item["_d"] = delta or Decimal(0)
            rows.append(item)
        if total_delta:
            for it in rows:
                it["contribution_pct"] = _pct(it["_d"], total_delta)
        rows.sort(key=lambda it: -abs(it["_d"]))
        for it in rows:
            it.pop("_d")
        if agg in ("SUM", "COUNT") and not r["truncated"]:
            gsum = sum((_dec(x["delta"]) or Decimal(0)) for x in rows)
            if total_delta is not None and gsum != total_delta:
                warnings.append(f"Group deltas sum to {gsum} but the total delta is "
                                f"{total_delta}; investigate before reporting.")
        elif r["truncated"]:
            warnings.append("More groups exist than could be fetched; group list is incomplete.")
        n = min(max(top_n, 1), 200)
        out.update(group_by=gc["name"], groups=rows[:n], groups_total=len(rows),
                   groups_omitted=max(len(rows) - n, 0))
    out["warnings"] = warnings
    out["as_of"] = tot["as_of"]
    return out


# ------------------------------------------------------------------ anomalies
def _bucket(d: date, gran: str) -> date:
    if gran == "week":
        return d - timedelta(days=d.weekday())
    if gran == "month":
        return d.replace(day=1)
    return d


def _bucket_end(b: date, gran: str) -> date:   # exclusive end of the bucket
    if gran == "week":
        return b + timedelta(days=7)
    if gran == "month":
        return (b.replace(day=28) + timedelta(days=4)).replace(day=1)
    return b + timedelta(days=1)


@mcp.tool()
async def detect_anomalies(source_id: str, table: str, date_column: str, measure: str,
                           aggregation: str = "SUM", granularity: str = "day",
                           start: str | None = None, end: str | None = None,
                           method: str = "robust", threshold: float | None = None,
                           where: str | None = None) -> dict:
    """Find unusual values in a measure over time (spikes, drops, zero days).

    granularity: day | week | month (weeks start Monday). method: robust (median/MAD, default,
    threshold 3.5), zscore (threshold 3), iqr (threshold 1.5 x IQR). Missing days are filled
    with 0 for SUM/COUNT and reported; the trailing partial week/month is excluded from scoring.
    AVG is only exact at day granularity. start/end are ISO dates, end exclusive."""
    src, _, schema, name, info, dialect = await _ctx(source_id, table)
    gran, method = granularity.lower(), method.lower()
    if gran not in ("day", "week", "month"):
        raise ValueError("granularity must be day, week or month.")
    if method not in ("robust", "zscore", "iqr"):
        raise ValueError("method must be robust, zscore or iqr.")
    dc = require_column(info, name, date_column)
    kind = col_kind(dc["type"])
    if kind not in ("date", "timestamp", "text"):
        raise ValueError(f"'{dc['name']}' ({dc['type']}) is not a date column.")
    agg, m = _measure(info, name, measure, aggregation)
    if agg == "AVG" and gran != "day":
        raise ValueError("AVG cannot be re-aggregated exactly into weeks/months; use "
                         "granularity='day', or SUM/COUNT/MIN/MAX.")
    thr = threshold if threshold is not None else {"robust": 3.5, "zscore": 3.0, "iqr": 1.5}[method]
    dx = day_expr(dc["name"], kind)
    cond = exp.Not(this=exp.Is(this=col(dc["name"]), expression=exp.Null()))
    if start:
        cond = exp.and_(cond, exp.GTE(this=col(dc["name"]), expression=date_literal(start, kind)))
    if end:
        cond = exp.and_(cond, exp.LT(this=col(dc["name"]), expression=date_literal(end, kind)))
    cond = _where(where, dialect, cond)
    q = (exp.select(_alias(dx, "d"), _alias(AGGS[agg](this=m), "v")).from_(table_expr(schema, name))
         .where(cond).group_by(dx))
    r = await _go(src, dialect, q, "detect_anomalies", 20_000)
    warnings = list(r["warnings"])
    if r["truncated"]:
        raise ValueError("Too many distinct days (>20000) for anomaly detection; narrow start/end.")
    daily: dict[date, Decimal] = {}
    bad = 0
    for dv, v in r["rows"]:
        try:
            daily[date.fromisoformat(str(dv)[:10])] = _dec(v)
        except (TypeError, ValueError):
            bad += 1
    if bad:
        warnings.append(f"{bad} rows had unparseable dates and were ignored.")
    daily = {k: v for k, v in daily.items() if v is not None}
    if len(daily) < 3:
        raise ValueError("Not enough data points to detect anomalies.")
    first, last = min(daily), max(daily)
    fill = agg in ("SUM", "COUNT")
    series: dict[date, Decimal] = {}
    missing_days = []
    day = first
    while day <= last:
        if day in daily:
            series[day] = daily[day]
        elif fill:
            series[day] = Decimal(0)
            missing_days.append(day)
        day += timedelta(days=1)
    # bucket (exact Decimal sums for SUM/COUNT; min/max re-aggregate exactly too)
    buckets: dict[date, list[Decimal]] = {}
    for d0, v in series.items():
        buckets.setdefault(_bucket(d0, gran), []).append(v)
    comb = {"SUM": sum, "COUNT": sum, "MIN": min, "MAX": max, "AVG": lambda xs: xs[0]}[agg]
    points = {b: comb(vs) for b, vs in sorted(buckets.items())}
    excluded = None
    if gran != "day":
        lastb = max(points)
        if last < _bucket_end(lastb, gran) - timedelta(days=1) and not end:
            excluded = str(lastb)
            points.pop(lastb)
            warnings.append(f"The latest {gran} ({excluded}) is incomplete and was excluded.")
    if len(points) < 8:
        warnings.append(f"Only {len(points)} periods; anomaly detection is unreliable with "
                        "fewer than 8.")
    vals = [float(v) for v in points.values()]
    keys = list(points)
    anomalies = []
    if len(vals) >= 3:
        if method == "robust":
            med = statistics.median(vals)
            mad = statistics.median(abs(v - med) for v in vals)
            center = med
            score = (lambda v: 0.6745 * (v - med) / mad) if mad else None
        elif method == "zscore":
            mu, sd = statistics.fmean(vals), statistics.pstdev(vals)
            center = mu
            score = (lambda v: (v - mu) / sd) if sd else None
        else:
            qs = statistics.quantiles(vals, n=4, method="inclusive")
            q1, q3 = qs[0], qs[2]
            iqr = q3 - q1
            center = statistics.median(vals)
            lo, hi = q1 - thr * iqr, q3 + thr * iqr
            score = (lambda v: 0.0 if lo <= v <= hi else (v - hi if v > hi else v - lo)) if iqr else None
        if score is None:
            warnings.append("The series is (nearly) constant, so no spread-based anomaly score "
                            "is possible.")
        else:
            for k, v in zip(keys, vals):
                s = score(v)
                flagged = (s != 0.0) if method == "iqr" else abs(s) > thr
                if flagged:
                    anomalies.append({"period": str(k), "value": _fmt(points[k]),
                                      "expected": round(center, 4), "score": round(s, 3),
                                      "direction": "high" if v > center else "low"})
    anomalies.sort(key=lambda a: -abs(a["score"]))
    out = {"table": name, "measure": f"{agg}({measure})", "granularity": gran,
           "method": method, "threshold": thr, "periods_scored": len(points),
           "range": [str(keys[0]), str(keys[-1])], "anomalies": anomalies[:50],
           "anomaly_count": len(anomalies),
           "summary": {"median": round(statistics.median(vals), 4),
                       "mean": round(statistics.fmean(vals), 4), "min": min(vals), "max": max(vals)},
           "missing_days_filled_with_zero": [str(x) for x in missing_days[:50]],
           "missing_days_total": len(missing_days), "warnings": warnings}
    if excluded:
        out["excluded_incomplete_period"] = excluded
    if len(points) <= 120:
        out["series"] = [[str(k), _fmt(v)] for k, v in points.items()]
    return out
