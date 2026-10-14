"""Integration tests against real PostgreSQL / MySQL / SQL Server servers.

Point them at disposable databases (the tests CREATE and DROP tables named cc_*):
    CC_TEST_PG_URL=host:port/db/user/password   (same for CC_TEST_MYSQL_URL, CC_TEST_MSSQL_URL)
Engines without a reachable server are skipped. Never point these at production data.
    pytest -m integration
"""
import os
import socket
from decimal import Decimal

import pyodbc
import pytest
import pytest_asyncio
from sqlalchemy import create_engine, text

from app.auth.passwords import hash_password
from app.config import get_settings
from app.connectors.sql import build_url
from app.db.models import Base, User
from app.db.session import SessionLocal, engine as meta_engine
from app.mcp_tools import data
from app.mcp_tools.server import current_user_id
from app.sources import service

pytestmark = pytest.mark.integration

def _env_cfg(var, **extra):
    raw = os.environ.get(var)
    if not raw:
        return None
    hostport, db, user, password = raw.split("/", 3)
    host, port = hostport.rsplit(":", 1)
    return dict(host=host, port=int(port), database=db, username=user, password=password,
                **extra)


ENGINES = {k: v for k, v in {
    "postgres": _env_cfg("CC_TEST_PG_URL"),
    "mysql": _env_cfg("CC_TEST_MYSQL_URL"),
    "mssql": _env_cfg("CC_TEST_MSSQL_URL", trust_server_cert=True),
}.items() if v}


N = 1200
EXPECTED_SUM = Decimal("1.10") * (N * (N + 1) // 2)  # 792660.00


def _mssql_driver():
    """Prefer the modern driver; fall back to the legacy one so the suite still runs locally."""
    have = pyodbc.drivers()
    for d in ("ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server", "SQL Server"):
        if d in have:
            return d
    return None


def _reachable(host, port):
    try:
        socket.create_connection((host, port), timeout=1).close()
        return True
    except OSError:
        return False


def _skip_reason(name):
    cfg = ENGINES[name]
    if not _reachable(cfg["host"], cfg["port"]):
        return f"{name} server not reachable"
    if name == "mssql" and not _mssql_driver():
        return "no SQL Server ODBC driver installed"
    return None


def _seed(name, cfg):
    """Create the same fixture on every engine. Real DDL, so FKs/PKs/views are introspected."""
    eng = create_engine(build_url(name, cfg))
    admin = eng
    if name == "mysql":  # ccuser only owns ccdb; fine for DDL there
        pass
    with eng.begin() as c:
        for stmt in ("DROP VIEW IF EXISTS big_orders", "DROP TABLE IF EXISTS cc_orders",
                     "DROP TABLE IF EXISTS cc_customers"):
            c.execute(text(stmt))
        c.execute(text("CREATE TABLE cc_customers(id INT PRIMARY KEY, name VARCHAR(50), "
                       "phone VARCHAR(20))"))
        c.execute(text("CREATE TABLE cc_orders(id INT PRIMARY KEY, customer_id INT, "
                       "amount DECIMAL(12,2), placed DATE, "
                       "FOREIGN KEY (customer_id) REFERENCES cc_customers(id))"))
        c.execute(text("INSERT INTO cc_customers VALUES (:i, :n, :p)"),
                  [{"i": i, "n": f"cust{i}", "p": f"900000000{i}"} for i in range(1, 6)])
        c.execute(text("INSERT INTO cc_orders VALUES (:i, :c, :a, '2026-01-15')"),
                  [{"i": i, "c": (i % 5) + 1, "a": f"{Decimal(i) * Decimal('1.10'):.2f}"}
                   for i in range(1, N + 1)])
        c.execute(text("CREATE VIEW big_orders AS SELECT id, amount FROM cc_orders "
                       "WHERE amount > 100"))
    admin.dispose()


@pytest_asyncio.fixture(params=["postgres", "mysql", "mssql"])
async def real(request, monkeypatch):
    name = request.param
    if name not in ENGINES:
        pytest.skip(f"CC_TEST_{ {'postgres': 'PG', 'mysql': 'MYSQL', 'mssql': 'MSSQL'}[name] }_URL not set")
    reason = _skip_reason(name)
    if reason:
        pytest.skip(reason)
    monkeypatch.setattr(get_settings(), "allow_loopback", True)
    cfg = dict(ENGINES[name])
    if name == "mssql":
        cfg["driver"] = _mssql_driver()
    _seed(name, cfg)
    async with meta_engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as s:
        u = User(email="r@x.in", name="R", password_hash=hash_password("x"))
        s.add(u)
        await s.commit()
        src = await service.create_source(s, u.id, f"real-{name}", name, dict(cfg))
        src.masked_columns = ["phone"]
        await s.commit()
    current_user_id.set(u.id)
    yield {"name": name, "src": src.id}
    service.SqlConnector.dispose(src.id)


async def _conn(real):
    async with SessionLocal() as s:
        return service.connector_for(await s.get(service.DataSource, real["src"]))


async def test_introspection(real):
    ov = await data.get_schema_overview(real["src"])
    tables = {t["table"].lower(): t for t in ov["tables"]}
    assert {"cc_customers", "cc_orders", "big_orders"} <= set(tables)
    assert tables["big_orders"]["kind"] == "view"
    d = await data.describe_table(real["src"], "cc_orders")
    assert [c.lower() for c in d["primary_key"]] == ["id"]
    assert d["foreign_keys"][0]["ref_table"].lower() == "cc_customers"
    assert len(d["sample"]["rows"]) == 3


async def test_exact_numbers_and_row_counts(real):
    r = await data.run_query(real["src"], "SELECT COUNT(*) AS n, SUM(amount) AS s FROM cc_orders")
    n, s = r["rows"][0]
    assert int(n) == N
    assert Decimal(str(s)) == EXPECTED_SUM          # exact, no float drift
    assert isinstance(s, str)                       # decimals travel as strings


async def test_truncation_flag(real):
    r = await data.run_query(real["src"], "SELECT id FROM cc_orders ORDER BY id", max_rows=100)
    assert r["row_count"] == 100 and r["truncated"] and "TRUNCATED" in r["warnings"][0]
    r = await data.run_query(real["src"], "SELECT id FROM cc_orders", max_rows=N)
    assert r["row_count"] == N and not r["truncated"]


async def test_dialect_specific_limit_injection(real):
    r = await data.run_query(real["src"], "SELECT id FROM cc_orders", max_rows=10)
    sql = r["executed_sql"].upper()
    assert ("TOP 11" in sql) if real["name"] == "mssql" else ("LIMIT 11" in sql)


async def test_join_and_aggregation(real):
    r = await data.run_query(
        real["src"],
        "SELECT c.name, COUNT(*) AS n FROM cc_orders o JOIN cc_customers c ON c.id = o.customer_id "
        "GROUP BY c.name ORDER BY c.name")
    assert len(r["rows"]) == 5 and sum(int(x[1]) for x in r["rows"]) == N


async def test_guard_blocks_writes_and_data_survives(real):
    for q in ("DELETE FROM cc_orders", "DROP TABLE cc_orders",
              "SELECT 1; DELETE FROM cc_orders"):
        with pytest.raises(ValueError):
            await data.run_query(real["src"], q)
    r = await data.run_query(real["src"], "SELECT COUNT(*) FROM cc_orders")
    assert int(r["rows"][0][0]) == N


async def test_engine_level_readonly_when_guard_bypassed(real):
    conn = await _conn(real)
    with pytest.raises(Exception):
        await conn.execute("DELETE FROM cc_orders WHERE id = 1", 10, 10)
    r = await data.run_query(real["src"], "SELECT COUNT(*) FROM cc_orders")
    assert int(r["rows"][0][0]) == N


async def test_timeout_cuts_off_runaway_query(real):
    conn = await _conn(real)
    heavy = "SELECT SUM(a.id * b.id + c.id) FROM cc_orders a, cc_orders b, cc_orders c"  # ~1.7B rows, no optimizer shortcut
    with pytest.raises(Exception):
        await conn.execute(heavy, 10, 1)
    r = await data.run_query(real["src"], "SELECT 1 AS ok")  # pool still healthy afterwards
    assert int(r["rows"][0][0]) == 1


async def test_masking(real):
    with pytest.raises(ValueError, match="masked"):
        await data.run_query(real["src"], "SELECT phone FROM cc_customers")
    with pytest.raises(ValueError, match="SELECT \\*"):
        await data.run_query(real["src"], "SELECT * FROM cc_customers")


async def test_unknown_table_suggestion(real):
    with pytest.raises(ValueError, match="Did you mean"):
        await data.run_query(real["src"], "SELECT * FROM cc_order")


async def test_bad_credentials_message_has_no_password(real):
    cfg = {**ENGINES[real["name"]], "password": "wrong-pass-XYZ",
           **({"driver": _mssql_driver()} if real["name"] == "mssql" else {})}
    async with SessionLocal() as s:
        with pytest.raises(service.SourceError) as e:
            await service.create_source(s, current_user_id.get(), "bad", real["name"], cfg)
    assert "wrong-pass-XYZ" not in str(e.value) and "Connection failed" in str(e.value)
