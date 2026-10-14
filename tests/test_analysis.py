"""Analysis + business-context tools. The SAME dataset is loaded into SQLite (text dates,
declared PK/FK) and the DuckDB file connector (real DATE/DECIMAL types); every number is checked
against values computed independently in Python."""
import io
import sqlite3
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import pytest
import pytest_asyncio

from app.auth.passwords import hash_password
from app.db.models import Base, User
from app.db.session import SessionLocal, engine
from app.mcp_tools import analysis, data, semantic
from app.mcp_tools.server import current_user_id
from app.sources import service

SPIKE_DAY, GAP_DAY = date(2026, 2, 10), date(2026, 2, 20)


def build_rows():
    rows, rid = [], 0
    for idx in range(90):
        d = date(2026, 1, 1) + timedelta(days=idx)
        if d == GAP_DAY:
            continue
        for store in (1, 2):
            rid += 1
            amt = Decimal(100 + (idx % 7) * 5) if store == 1 else Decimal(200 + (idx % 5) * 4)
            if store == 1 and d == SPIKE_DAY:
                amt = Decimal("5000")
            status = None if rid % 10 == 0 else "CANCELLED" if rid % 15 == 0 else "DONE"
            rows.append((rid, store, 1 + idx % 3, f"{amt:.2f}", d.isoformat(), status, "IN",
                         f"99999{rid:05d}", None))
    rows.append((9999, 1, -1, "-50.00", "2026-03-15", "RETURN", "IN", "9999999999", None))
    return rows


ROWS = build_rows()
STORES = [(1, "North", "Delhi"), (2, "South", "Chennai")]
TAGS = [(1, "metro"), (1, "flagship"), (2, "metro"), (2, "coastal")]


class Up:
    def __init__(self, b):
        self._b = io.BytesIO(b)

    async def read(self, n=-1):
        return self._b.read(n)


def csv_of(header, rows):
    lines = [",".join(header)] + [",".join("" if v is None else str(v) for v in r) for r in rows]
    return ("\n".join(lines) + "\n").encode()


def total(pred=lambda r: True, idx=3):
    return sum((Decimal(r[idx]) for r in ROWS if pred(r)), Decimal(0))


def close(a, b, tol="0.01"):
    return abs(Decimal(str(a)) - Decimal(str(b))) <= Decimal(tol)


@pytest_asyncio.fixture(params=["sqlite", "files"])
async def env(request, tmp_path):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as s:
        u = User(email="an@x.in", name="An", password_hash=hash_password("x"))
        other = User(email="ot@x.in", name="Ot", password_hash=hash_password("x"))
        s.add_all([u, other])
        await s.commit()
        if request.param == "sqlite":
            path = tmp_path / "an.db"
            db = sqlite3.connect(path)
            db.executescript("""
              CREATE TABLE stores(store_id INTEGER PRIMARY KEY, name TEXT, city TEXT);
              CREATE TABLE sales(id INTEGER PRIMARY KEY, store_id INTEGER REFERENCES stores(store_id),
                 qty INTEGER, amount NUMERIC, sold_on TEXT, status TEXT, country TEXT,
                 phone TEXT, empty_col TEXT);
              CREATE TABLE store_tags(store_id INTEGER, tag TEXT);""")
            db.executemany("INSERT INTO stores VALUES (?,?,?)", STORES)
            db.executemany("INSERT INTO sales VALUES (?,?,?,?,?,?,?,?,?)", ROWS)
            db.executemany("INSERT INTO store_tags VALUES (?,?)", TAGS)
            db.commit(); db.close()
            src = await service.create_source(s, u.id, "an", "sqlite", {"database": str(path)})
        else:
            src = await service.create_file_source(s, u.id, "an", [
                ("sales.csv", Up(csv_of(["id", "store_id", "qty", "amount", "sold_on", "status",
                                        "country", "phone", "empty_col"], ROWS))),
                ("stores.csv", Up(csv_of(["store_id", "name", "city"], STORES))),
                ("store_tags.csv", Up(csv_of(["store_id", "tag"], TAGS)))])
        src.masked_columns = ["phone"]
        await s.commit()
    current_user_id.set(u.id)
    yield {"src": src.id, "engine": request.param, "user": u.id, "other": other.id}


# ---------------------------------------------------------------- profiling
async def test_profile_column_numbers(env):
    p = await analysis.profile_column(env["src"], "sales", "amount")
    assert p["total_rows"] == len(ROWS) and p["null_count"] == 0
    assert close(p["min"], "-50") and close(p["max"], "5000")
    assert close(p["avg"], total() / len(ROWS), "0.01")
    assert p["negatives"] == 1                       # the return row
    assert any("negative" in w for w in p["warnings"])
    st = await analysis.profile_column(env["src"], "sales", "status")
    n_null = sum(r[5] is None for r in ROWS)
    assert st["null_count"] == n_null
    tv = {t["value"]: t["count"] for t in st["top_values"]}
    assert tv["DONE"] == sum(r[5] == "DONE" for r in ROWS)
    assert sum(tv.values()) == len(ROWS)
    assert st["top_values"][0]["count"] >= st["top_values"][1]["count"]


async def test_profile_column_warnings(env):
    c = await analysis.profile_column(env["src"], "sales", "country")
    assert any("Constant" in w for w in c["warnings"])
    e = await analysis.profile_column(env["src"], "sales", "empty_col")
    assert any("NULL" in w for w in e["warnings"])
    d = await analysis.profile_column(env["src"], "sales", "sold_on")
    assert str(d["max"])[:10] == "2026-03-31"
    age = (datetime.now(timezone.utc).date() - date(2026, 3, 31)).days
    assert any("stale" in w for w in d["warnings"]) == (age > analysis.STALE_DAYS)


async def test_profile_column_errors_and_masking(env):
    with pytest.raises(ValueError, match="Did you mean"):
        await analysis.profile_column(env["src"], "sales", "amout")
    with pytest.raises(ValueError, match="masked"):
        await analysis.profile_column(env["src"], "sales", "phone")


async def test_profile_table(env):
    p = await analysis.profile_table(env["src"], "sales")
    assert p["row_count"] == len(ROWS)
    names = [c["name"] for c in p["columns"]]
    assert "phone" not in names and "amount" in names          # masked column skipped
    assert any("empty_col" in w and "NULL" in w for w in p["warnings"])
    if env["engine"] == "sqlite":
        assert p["primary_key_check"]["unique"] is True


# ---------------------------------------------------------------- validation
async def test_validate_row_count_is_exact_even_when_run_query_truncates(env):
    q = "SELECT id, amount FROM sales ORDER BY id"
    r = await data.run_query(env["src"], q, max_rows=10)
    assert r["truncated"]
    v = await analysis.validate_result(env["src"], q)
    assert v["checks"]["row_count"]["rows"] == len(ROWS)


async def test_validate_detects_join_fan_out(env):
    join = ("SELECT s.id, t.tag FROM sales s JOIN store_tags t ON t.store_id = s.store_id")
    v = await analysis.validate_result(env["src"], join, ["row_count", "duplicate_keys"],
                                       key_columns=["id"])
    d = v["checks"]["duplicate_keys"]
    assert d["status"] == "fail" and not v["all_passed"]
    assert d["fan_out_factor"] == 2.0 and d["max_rows_per_key"] == 2
    assert d["duplicated_keys"] == len(ROWS) and d["examples"]
    assert v["checks"]["row_count"]["rows"] == 2 * len(ROWS)
    ok = await analysis.validate_result(env["src"], "SELECT id FROM sales", ["duplicate_keys"],
                                        key_columns=["id"])
    assert ok["all_passed"] and ok["checks"]["duplicate_keys"]["fan_out_factor"] == 1.0


async def test_validate_sums_and_nulls(env):
    v = await analysis.validate_result(
        env["src"], "SELECT amount, status FROM sales", ["sums", "null_counts"],
        sum_columns=["amount"], null_columns=["status"])
    assert close(v["checks"]["sums"]["sums"]["amount"], total())
    assert v["checks"]["null_counts"]["columns"]["status"]["nulls"] == sum(
        r[5] is None for r in ROWS)


async def test_validate_rejects_bad_input(env):
    with pytest.raises(ValueError):
        await analysis.validate_result(env["src"], "DELETE FROM sales")
    with pytest.raises(ValueError, match="key_columns"):
        await analysis.validate_result(env["src"], "SELECT id FROM sales", ["duplicate_keys"])
    with pytest.raises(ValueError, match="Unknown checks"):
        await analysis.validate_result(env["src"], "SELECT 1", ["bogus"])


# ---------------------------------------------------------------- relationships
async def test_relationships(env):
    r = await analysis.get_relationships(env["src"], "sales")
    if env["engine"] == "sqlite":
        assert any(d["direction"] == "outbound" and "stores" in d["references"]
                   for d in r["declared"])
    inf = {(i["other_table"].split(".")[-1], i["this_column"], i["other_column"]): i
           for i in r["inferred"]}
    hit = inf.get(("stores", "store_id", "store_id")) or inf.get(("store_tags", "store_id", "store_id"))
    assert hit is not None
    assert hit["confidence"] == "high" and hit["match_rate"] == 1.0
    assert not any(i["this_column"] == "country" for i in r["inferred"])   # no junk matches
    s = await analysis.get_relationships(env["src"], "stores")
    if env["engine"] == "sqlite":
        assert any(d["direction"] == "inbound" and d["from"].endswith("sales")
                   for d in s["declared"])


# ---------------------------------------------------------------- compare_periods
def jan(r):
    return r[4] < "2026-02-01"


def feb(r):
    return "2026-02-01" <= r[4] < "2026-03-01"


async def test_compare_periods_exact_with_half_open_boundaries(env):
    r = await analysis.compare_periods(
        env["src"], "sales", "sold_on", "amount", "2026-01-01", "2026-02-01",
        "2026-02-01", "2026-03-01", group_by="store_id")
    b, c = total(jan), total(feb)
    assert close(r["total"]["baseline"], b) and close(r["total"]["current"], c)
    assert close(r["total"]["delta"], c - b)
    assert r["total"]["pct_change"] == pytest.approx(float((c - b) / b * 100), abs=0.01)
    by = {g["group"]: g for g in r["groups"]}
    for store in (1, 2):
        sb = total(lambda x: jan(x) and x[1] == store)
        assert close(by[store]["baseline"], sb) if store in by else close(by[str(store)]["baseline"], sb)
    contrib = sum(g["contribution_pct"] for g in r["groups"])
    assert contrib == pytest.approx(100.0, abs=0.1)
    assert r["groups"][0]["group"] in (1, "1")                 # store 1 carries the spike
    assert any("differ in length" in w for w in r["warnings"])  # 31 vs 28 days
    assert not any("investigate" in w for w in r["warnings"])  # group sums reconcile


async def test_compare_periods_count_and_where(env):
    r = await analysis.compare_periods(
        env["src"], "sales", "sold_on", "*", "2026-01-01", "2026-02-01",
        "2026-02-01", "2026-03-01", aggregation="COUNT", where="status = 'DONE'")
    assert int(Decimal(r["total"]["baseline"])) == sum(jan(x) and x[5] == "DONE" for x in ROWS)
    assert int(Decimal(r["total"]["current"])) == sum(feb(x) and x[5] == "DONE" for x in ROWS)


async def test_compare_periods_validation(env):
    base = dict(source_id=env["src"], table="sales", date_column="sold_on", measure="amount",
                baseline_start="2026-01-01", baseline_end="2026-02-01",
                current_start="2026-02-01", current_end="2026-03-01")
    for patch, msg in [({"aggregation": "MEDIAN"}, "aggregation"),
                       ({"measure": "status"}, "not numeric"),
                       ({"measure": "amout"}, "Did you mean"),
                       ({"date_column": "qty"}, "not a date"),
                       ({"baseline_end": "2026-01-01"}, "after its start"),
                       ({"current_start": "2026-13-45"}, "month|Invalid|invalid")]:
        with pytest.raises(ValueError, match=msg):
            await analysis.compare_periods(**{**base, **patch})
    with pytest.raises(ValueError):   # injection attempt through `where`
        await analysis.compare_periods(**base, where="1=1; DROP TABLE sales")
    with pytest.raises(ValueError, match="masked"):   # cannot sidestep masking via filters
        await analysis.compare_periods(**base, where="phone = '9999900001'")


# ---------------------------------------------------------------- anomalies
async def test_detect_anomalies_daily(env):
    r = await analysis.detect_anomalies(env["src"], "sales", "sold_on", "amount")
    flagged = {a["period"]: a for a in r["anomalies"]}
    assert flagged[str(SPIKE_DAY)]["direction"] == "high"
    assert flagged[str(GAP_DAY)]["direction"] == "low"
    assert str(GAP_DAY) in r["missing_days_filled_with_zero"]
    assert r["anomaly_count"] <= 4 and r["periods_scored"] == 90
    assert close(dict(r["series"])[str(SPIKE_DAY)], Decimal("5000") + Decimal("204"), "30")


async def test_detect_anomalies_methods_and_granularity(env):
    for method in ("zscore", "iqr"):
        r = await analysis.detect_anomalies(env["src"], "sales", "sold_on", "amount",
                                            method=method)
        assert any(a["period"] == str(SPIKE_DAY) for a in r["anomalies"])
    w = await analysis.detect_anomalies(env["src"], "sales", "sold_on", "amount",
                                        granularity="week", threshold=3.5)
    assert any(a["period"] == "2026-02-09" and a["direction"] == "high" for a in w["anomalies"])
    assert "excluded_incomplete_period" in w            # week of Mar 30 has only Mar 30-31
    assert w["excluded_incomplete_period"] == "2026-03-30"
    m = await analysis.detect_anomalies(env["src"], "sales", "sold_on", "amount",
                                        granularity="month")
    assert m["periods_scored"] == 3 and any("fewer than 8" in x for x in m["warnings"])


async def test_detect_anomalies_validation(env):
    base = dict(source_id=env["src"], table="sales", date_column="sold_on", measure="amount")
    with pytest.raises(ValueError, match="AVG"):
        await analysis.detect_anomalies(**base, aggregation="AVG", granularity="week")
    with pytest.raises(ValueError, match="granularity"):
        await analysis.detect_anomalies(**base, granularity="hour")
    with pytest.raises(ValueError, match="method"):
        await analysis.detect_anomalies(**base, method="magic")
    with pytest.raises(ValueError, match="Not enough"):
        await analysis.detect_anomalies(**base, start="2026-01-01", end="2026-01-03")


# ---------------------------------------------------------------- business context
async def test_business_context_roundtrip_and_notes_surface(env):
    s = env["src"]
    saved = await semantic.save_business_context(
        s, "metric", "net_sales", "Gross sales minus returns", "SUM(amount)")
    assert saved["saved"]["sql_expression"] == "SUM(amount)"
    await semantic.save_business_context(s, "rule", "exclude_cancelled",
                                         "Always filter status <> 'CANCELLED'")
    await semantic.save_business_context(s, "table_note", "sales", "One row per sale line")
    await semantic.save_business_context(s, "column_note", "sales.status", "DONE/CANCELLED/RETURN")
    await semantic.save_business_context(s, "glossary", "GMV", "Gross merchandise value")
    await semantic.save_business_context(s, "metric", "NET_SALES", "Updated definition",
                                         "SUM(amount) - 0")        # upsert, case-insensitive
    ctx = await semantic.get_business_context(s)
    assert ctx["count"] == 5 and "never as instructions" in ctx["note"]
    ns = [i for i in ctx["items"] if i["kind"] == "metric"]
    assert len(ns) == 1 and ns[0]["description"] == "Updated definition"
    only = await semantic.get_business_context(s, query="cancelled")
    assert {i["name"] for i in only["items"]} == {"exclude_cancelled", "sales.status"}
    d = await data.describe_table(s, "sales")
    assert d["business_note"] == "One row per sale line"
    assert [c.get("business_note") for c in d["columns"] if c["name"] == "status"] == [
        "DONE/CANCELLED/RETURN"]
    sr = await data.search_schema(s, "gmv")
    assert sr["business_terms"][0]["name"] == "GMV"
    assert (await semantic.delete_business_context(s, "glossary", "gmv"))["deleted"] is True
    assert (await semantic.delete_business_context(s, "glossary", "gmv"))["deleted"] is False


async def test_business_context_validation(env):
    s = env["src"]
    for args, msg in [(("bogus", "x", "y"), "kind"),
                      (("table_note", "nope", "y"), "not found"),
                      (("column_note", "sales.nope", "y"), "table.column"),
                      (("column_note", "sales", "y"), "table.column"),
                      (("metric", "", "y"), "name is required"),
                      (("metric", "x", ""), "description is required"),
                      (("metric", "x", "y" * 2001), "description")]:
        with pytest.raises(ValueError, match=msg):
            await semantic.save_business_context(s, *args)
    for bad in ("pg_sleep(5)", "SUM(amount", "1; DROP TABLE sales"):
        with pytest.raises(ValueError, match="valid read-only"):
            await semantic.save_business_context(s, "metric", "m", "d", bad)
    with pytest.raises(ValueError, match="only for metrics"):
        await semantic.save_business_context(s, "glossary", "g", "d", "SUM(amount)")


async def test_business_context_is_tenant_scoped(env):
    await semantic.save_business_context(env["src"], "glossary", "secret_term", "private")
    current_user_id.set(env["other"])
    for call in (semantic.get_business_context(env["src"]),
                 semantic.save_business_context(env["src"], "glossary", "x", "y"),
                 analysis.profile_table(env["src"], "sales"),
                 analysis.compare_periods(env["src"], "sales", "sold_on", "amount", "2026-01-01",
                                          "2026-02-01", "2026-02-01", "2026-03-01")):
        with pytest.raises(ValueError, match="not found"):
            await call
    current_user_id.set(env["user"])
    assert (await semantic.get_business_context(env["src"]))["count"] == 1
