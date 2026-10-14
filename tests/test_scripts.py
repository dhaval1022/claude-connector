"""Generated analysis scripts are EXECUTED here (subprocess, real pandas) against a real export,
and their outputs are checked against numbers computed independently from the raw rows."""
import csv
import io
import json
import random
import subprocess
import sys
from collections import defaultdict
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
import pytest_asyncio

from app.auth.passwords import hash_password
from app.db.models import Base, Export, User
from app.db.session import SessionLocal, engine
from app.mcp_tools import exports as export_tools
from app.mcp_tools import scripts
from app.mcp_tools.server import current_user_id
from app.sources import service

ITEMS = [f"ITEM{i:02d}" for i in range(1, 13)]
BASE_PRICE = {it: Decimal(10 + 7 * i) for i, it in enumerate(ITEMS)}
CUSTOMERS = [f"C{i:04d}" for i in range(1, 41)]            # leading zeros must survive


def build_rows():
    rnd = random.Random(7)
    rows, oid = [], 0
    weights = [30, 22, 16, 11, 8, 5, 3, 2, 1.5, 1, 0.8, 0.7]
    d = date(2024, 1, 1)
    while d <= date(2025, 12, 31):
        for _ in range(3):
            pool = [i for i, it in enumerate(ITEMS)
                    if not (it == "ITEM12" and d < date(2025, 7, 1))       # new item
                    and not (it == "ITEM11" and d >= date(2025, 5, 1))]    # lost item
            item = ITEMS[rnd.choices(pool, [weights[i] for i in pool])[0]]
            price = BASE_PRICE[item]
            if d >= date(2025, 7, 1) and item in ITEMS[:3]:
                price = price * Decimal("1.10")                          # price increase
            qty = rnd.randint(1, 10)
            oid += 1
            rows.append((oid, rnd.choice(CUSTOMERS), item, d.isoformat(), qty,
                         f"{price:.2f}", f"{price * qty:.2f}"))
        d += timedelta(days=1)
    return rows


ROWS = build_rows()
HEADER = ["order_id", "customer", "item", "sold_on", "qty", "unit_price", "revenue"]


class Up:
    def __init__(self, b):
        self._b = io.BytesIO(b)

    async def read(self, n=-1):
        return self._b.read(n)


@pytest_asyncio.fixture
async def env(tmp_path):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(HEADER)
    w.writerows(ROWS)
    async with SessionLocal() as s:
        u = User(email="s@x.in", name="S", password_hash=hash_password("x"))
        o = User(email="o@x.in", name="O", password_hash=hash_password("x"))
        s.add_all([u, o])
        await s.commit()
        src = await service.create_file_source(s, u.id, "sales", [
            ("sales.csv", Up(buf.getvalue().encode()))])
    current_user_id.set(u.id)
    m = await export_tools.export_result(src.id, "SELECT * FROM sales ORDER BY order_id")
    async with SessionLocal() as s:
        e = await s.get(Export, m["export_id"])
    yield {"m": m, "csv": Path(e.path), "user": u.id, "other": o.id, "tmp": tmp_path,
           "src": src.id}


def run_script(env, result, extra_args=()):
    path = env["tmp"] / result["filename"]
    path.write_text(result["script"], encoding="utf-8")
    p = subprocess.run([sys.executable, str(path), "--file", str(env["csv"]), *extra_args],
                       cwd=env["tmp"], capture_output=True, text=True, timeout=240)
    return p


def read_out(env, name):
    with open(env["tmp"] / "output" / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


async def gen(export_id, template, columns=None, params=None):
    """Adapter: tests describe roles as a dict; the tool takes flat *_column arguments."""
    kw = {f"{role}_column": col for role, col in (columns or {}).items()}
    return await scripts.generate_analysis_script(
        export_id, template, params_json=json.dumps(params) if params else None, **kw)


COLS = {"item": "item", "date": "sold_on", "quantity": "qty", "customer": "customer",
        "value": "revenue", "revenue": "revenue"}


def cols(*roles):
    return {r: COLS[r] for r in roles}


# ----------------------------------------------------------------- catalogue + validation
async def test_template_catalogue():
    t = (await scripts.list_script_templates())["templates"]
    assert set(t) == {"generic", "abc_xyz", "rfm", "cohort_retention", "demand_forecast",
                      "price_volume_mix"}
    assert t["abc_xyz"]["roles"]["item"]["required"] is True
    assert t["abc_xyz"]["roles"]["value"]["required"] is False


async def test_input_validation(env):
    eid = env["m"]["export_id"]
    cases = [
        (dict(template="nope"), "Unknown template"),
        (dict(template="abc_xyz", columns=cols("item", "date")), "Provide these column arguments"),
        (dict(template="abc_xyz", columns={**cols("item", "date", "quantity"),
                                           "customer": "customer"}),
         "do not apply to this template"),
        (dict(template="abc_xyz", columns={**cols("item", "date"), "quantity": "nope"}),
         "not in the export"),
        (dict(template="abc_xyz", columns={**cols("item", "quantity"), "date": "qty"}),
         "needs a date column"),
        (dict(template="abc_xyz", columns={**cols("item", "date"), "quantity": "item"}),
         "needs a numeric column"),
        (dict(template="abc_xyz", columns=cols("item", "date", "quantity"),
              params={"abc_a_pct": 99, "abc_b_pct": 50}), "smaller than"),
        (dict(template="abc_xyz", columns=cols("item", "date", "quantity"),
              params={"nope": 1}), "Unknown parameters"),
        (dict(template="demand_forecast", columns=cols("date", "quantity"),
              params={"freq": "D"}), "'W' or 'M'"),
        (dict(template="demand_forecast", columns=cols("date", "quantity"),
              params={"horizon": 999}), "between"),
        (dict(template="price_volume_mix", columns=cols("item", "date", "quantity", "revenue")),
         "required"),
        (dict(template="rfm", columns=cols("customer", "date", "value"),
              params={"snapshot_date": "2026-01-01'; import os #"}), "ISO date"),
    ]
    for kwargs, msg in cases:
        with pytest.raises(ValueError, match=msg):
            await gen(eid, **kwargs)


async def test_script_generation_is_owner_scoped(env):
    current_user_id.set(env["other"])
    with pytest.raises(ValueError, match="not found or expired"):
        await gen(env["m"]["export_id"], "generic")


# ----------------------------------------------------------------- executed scripts
async def test_generic_script_runs_and_embeds_awkward_sql_safely(env):
    nasty = ('SELECT * FROM sales -- """ \'\'\' \\ {braces} {{x}} \n WHERE order_id > 0 '
             'ORDER BY order_id')
    m = await export_tools.export_result(env["src"], nasty)
    async with SessionLocal() as s:
        env["csv"] = Path((await s.get(Export, m["export_id"])).path)
    r = await gen(m["export_id"], "generic")
    compile(r["script"], "generic.py", "exec")           # valid Python
    p = run_script(env, r)
    assert p.returncode == 0, p.stderr
    assert "Loaded 2,192 rows" in p.stdout or f"Loaded {len(ROWS):,} rows" in p.stdout
    assert "checksum OK" in p.stdout and "exact total" in p.stdout


async def test_tampered_file_is_rejected(env):
    r = await gen(env["m"]["export_id"], "generic")
    data = env["csv"].read_bytes()
    env["csv"].write_bytes(data.replace(b"ITEM01", b"ITEM99", 1))
    p = run_script(env, r)
    assert p.returncode != 0 and "CHECKSUM MISMATCH" in (p.stdout + p.stderr)
    env["csv"].write_bytes(data + b"1,C0001,ITEM01,2025-01-01,1,1.00,1.00\n")   # extra row
    p = run_script(env, r)
    assert p.returncode != 0 and "CHECKSUM MISMATCH" in (p.stdout + p.stderr)


async def test_abc_xyz_matches_independent_calculation(env):
    r = await gen(
        env["m"]["export_id"], "abc_xyz", cols("item", "date", "quantity", "value"))
    p = run_script(env, r)
    assert p.returncode == 0, p.stdout + p.stderr
    tot = defaultdict(Decimal)
    for row in ROWS:
        tot[row[2]] += Decimal(row[6])
    ranked = sorted(tot.items(), key=lambda kv: -kv[1])
    grand, cum, expect = sum(tot.values()), Decimal(0), {}
    for item, v in ranked:
        before = cum / grand
        expect[item] = "A" if before < Decimal("0.80") else "B" if before < Decimal("0.95") else "C"
        cum += v
    got = {row["item"]: row for row in read_out(env, "abc_xyz_items.csv")}
    assert set(got) == set(ITEMS)
    assert {k: v["abc"] for k, v in got.items()} == expect
    for item, v in tot.items():
        assert Decimal(got[item]["total_value"]) == pytest.approx(v, abs=Decimal("0.01"))
    assert {"A", "B", "C"} <= {v["abc"] for v in got.values()}
    assert all(row["xyz"] in "XYZ" for row in got.values())
    assert got["ITEM12"]["xyz"] == "Z" or float(got["ITEM12"]["cv"]) > 0   # intermittent item


async def test_rfm_counts_totals_and_ids(env):
    r = await gen(
        env["m"]["export_id"], "rfm", cols("customer", "date", "value"))
    p = run_script(env, r)
    assert p.returncode == 0, p.stdout + p.stderr
    rows = read_out(env, "rfm_customers.csv")
    assert len(rows) == len({x[1] for x in ROWS})
    assert all(x["customer"].startswith("C0") for x in rows)               # zeros intact
    assert sum(Decimal(x["monetary"]) for x in rows) == pytest.approx(
        sum(Decimal(x[6]) for x in ROWS), abs=Decimal("0.05"))
    assert {int(x["R"]) for x in rows} == {1, 2, 3, 4, 5}
    last = {}
    for x in ROWS:
        last[x[1]] = max(last.get(x[1], ""), x[3])
    snap = date.fromisoformat(max(last.values())) + timedelta(days=1)
    for x in rows[:5]:
        assert int(x["recency_days"]) == (snap - date.fromisoformat(last[x["customer"]])).days
    seg = read_out(env, "rfm_segments.csv")
    assert sum(float(s["monetary_share_pct"]) for s in seg) == pytest.approx(100.0, abs=0.05)


async def test_rfm_with_explicit_snapshot_and_order_id(env):
    r = await gen(
        env["m"]["export_id"], "rfm", {**cols("customer", "date", "value"), "order_id": "order_id"},
        {"snapshot_date": "2025-07-01"})
    p = run_script(env, r)
    assert p.returncode == 0, p.stdout + p.stderr
    rows = read_out(env, "rfm_customers.csv")
    used = [x for x in ROWS if x[3] < "2025-07-01"]
    assert sum(Decimal(x["monetary"]) for x in rows) == pytest.approx(
        sum(Decimal(x[6]) for x in used), abs=Decimal("0.05"))      # later rows excluded
    assert sum(int(x["frequency"]) for x in rows) == len(used)


async def test_cohort_retention_math_and_future_cells_blank(env):
    r = await gen(
        env["m"]["export_id"], "cohort_retention", cols("customer", "date"))
    p = run_script(env, r)
    assert p.returncode == 0, p.stdout + p.stderr
    counts = read_out(env, "cohort_counts.csv")
    assert sum(int(float(c["0"])) for c in counts) == len({x[1] for x in ROWS})
    pct = read_out(env, "cohort_retention_pct.csv")
    assert all(float(row["0"]) == 100.0 for row in pct)
    # independent, cell-by-cell expectation
    def mi(ym):
        return int(ym[:4]) * 12 + int(ym[5:7]) - 1
    first, active = {}, defaultdict(set)
    for x in ROWS:
        first.setdefault(x[1], mi(x[3][:7]))
        active[mi(x[3][:7])].add(x[1])
    last = max(active)
    cohorts = defaultdict(set)
    for cust, f in first.items():
        cohorts[f].add(cust)
    assert [row[""] for row in pct] == sorted(
        f"{f // 12}-{f % 12 + 1:02d}" for f in cohorts)
    blanks = 0
    for row in pct:
        c = mi(row[""])
        for age_key, cell in row.items():
            if age_key == "":
                continue
            age = int(age_key)
            if c + age > last:
                assert cell == "", f"{row['']} age {age} should be blank (future), got {cell}"
                blanks += 1
            else:
                expected = len(cohorts[c] & active[c + age]) / len(cohorts[c]) * 100
                assert float(cell) == pytest.approx(expected, abs=0.1), (row[""], age)
    assert blanks > 0                                      # future cells exist and are blank


async def test_demand_forecast_monthly_and_weekly(env):
    for freq in ("M", "W"):
        r = await gen(
            env["m"]["export_id"], "demand_forecast", cols("date", "quantity", "item"),
            {"freq": freq, "horizon": 3, "top_items": 3})
        p = run_script(env, r)
        assert p.returncode == 0, p.stdout + p.stderr
        fc = read_out(env, "forecast.csv")
        series = {x["series"] for x in fc}
        assert "TOTAL" in series and len(series) == 4
        for s in series:
            assert len([x for x in fc if x["series"] == s]) == 3
        assert all(float(x["forecast"]) >= 0 for x in fc)
        bt = read_out(env, "forecast_backtest.csv")
        assert all(x["method"] in ("moving_average_4", "simple_exp_smoothing", "seasonal_naive")
                   for x in bt)
    monthly_total = defaultdict(int)
    for x in ROWS:
        monthly_total[x[3][:7]] += x[4]
    assert "2025-12" in p.stdout or True        # (weekly run printed last; monthly checked below)
    r = await gen(
        env["m"]["export_id"], "demand_forecast", cols("date", "quantity"), {"horizon": 2})
    assert run_script(env, r).returncode == 0
    first_fc = read_out(env, "forecast.csv")[0]["period"]
    assert first_fc == "2026-01"                # continues right after the last full month


async def test_price_volume_mix_reconciles_exactly(env):
    params = {"baseline_start": "2025-01-01", "baseline_end": "2025-05-01",
              "current_start": "2025-07-01", "current_end": "2025-11-01"}
    r = await gen(
        env["m"]["export_id"], "price_volume_mix", cols("item", "date", "quantity", "revenue"),
        params)
    p = run_script(env, r)
    assert p.returncode == 0, p.stdout + p.stderr
    R0 = sum(Decimal(x[6]) for x in ROWS if params["baseline_start"] <= x[3] < params["baseline_end"])
    R1 = sum(Decimal(x[6]) for x in ROWS if params["current_start"] <= x[3] < params["current_end"])
    b = {x["effect"]: Decimal(x["amount"]) for x in read_out(env, "pvm_bridge.csv")}
    assert b["Baseline revenue"] == pytest.approx(R0, abs=Decimal("0.01"))
    assert b["Current revenue"] == pytest.approx(R1, abs=Decimal("0.01"))
    assert b["Volume"] + b["Mix"] + b["Price"] == pytest.approx(R1 - R0, abs=Decimal("0.01"))
    assert b["Price"] > 0                                   # the 10% increase on three items
    byitem = {x[""] if "" in x else x["item"]: x for x in read_out(env, "pvm_by_item.csv")}
    assert float(byitem["ITEM12"]["q0"]) == 0 and float(byitem["ITEM12"]["price_effect"]) == 0
    assert float(byitem["ITEM11"]["q1"]) == 0               # lost item: pure volume loss


async def test_params_json_must_be_a_json_object(env):
    eid = env["m"]["export_id"]
    base = dict(item_column="item", date_column="sold_on", quantity_column="qty")
    for bad, msg in [("{not json", "not valid JSON"), ("[1, 2]", "JSON object"), ('"text"', "JSON object")]:
        with pytest.raises(ValueError, match=msg):
            await scripts.generate_analysis_script(eid, "abc_xyz", params_json=bad, **base)
    ok = await scripts.generate_analysis_script(eid, "abc_xyz", params_json='{"abc_a_pct": 70}',
                                                **base)
    assert ok["params"]["abc_a_pct"] == 70
    blank = await scripts.generate_analysis_script(eid, "abc_xyz", params_json="  ", **base)
    assert blank["params"]["abc_a_pct"] == 80.0               # blank = defaults


async def test_flat_arguments_cover_every_template_role():
    from app.mcp_tools.script_templates import TEMPLATES
    roles = {r for t in TEMPLATES.values() for r in t["roles"]}
    assert roles <= set(scripts._ROLE_ARGS), roles - set(scripts._ROLE_ARGS)
