import sqlite3

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.auth.passwords import hash_password
from app.db.models import AuditLog, Base, DataSource, User
from app.db.session import SessionLocal, engine
from app.mcp_tools import data
from app.mcp_tools.server import current_user_id, list_data_sources
from app.sources import service
from app.sources.crypto import decrypt_config, encrypt_config
from app.sources.netcheck import HostBlocked, check_host


@pytest_asyncio.fixture
async def env(tmp_path):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    path = tmp_path / "shop.db"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, phone TEXT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers(id),
                            amount NUMERIC, placed TEXT);
        CREATE VIEW big_orders AS SELECT * FROM orders WHERE amount > 100;
    """)
    db.executemany("INSERT INTO customers VALUES (?,?,?)",
                   [(i, f"cust{i}", f"9{i:09d}") for i in range(1, 6)])
    db.executemany("INSERT INTO orders VALUES (?,?,?,?)",
                   [(i, (i % 5) + 1, f"{i}.10", "2026-01-01") for i in range(1, 1201)])
    db.commit(); db.close()
    async with SessionLocal() as s:
        a = User(email="a@x.in", name="A", password_hash=hash_password("x"))
        b = User(email="b@x.in", name="B", password_hash=hash_password("x"))
        s.add_all([a, b]); await s.commit()
        src = await service.create_source(s, a.id, "Shop", "sqlite", {"database": str(path)})
        src.masked_columns = ["phone"]
        await s.commit()
    current_user_id.set(a.id)
    yield {"a": a.id, "b": b.id, "src": src.id, "path": path}


async def test_introspection_and_overview(env):
    ov = await data.get_schema_overview(env["src"])
    names = {t["table"]: t for t in ov["tables"]}
    assert set(names) == {"customers", "orders", "big_orders"}
    assert names["big_orders"]["kind"] == "view"
    d = await data.describe_table(env["src"], "orders")
    assert d["primary_key"] == ["id"]
    assert d["foreign_keys"][0]["ref_table"] == "customers"
    assert len(d["sample"]["rows"]) == 3


async def test_masked_column_hidden_in_describe_and_blocked_in_query(env):
    d = await data.describe_table(env["src"], "customers")
    assert [c["masked"] for c in d["columns"] if c["name"] == "phone"] == [True]
    assert "phone" not in d["sample"]["columns"]
    with pytest.raises(ValueError, match="masked"):
        await data.run_query(env["src"], "SELECT phone FROM customers")
    with pytest.raises(ValueError, match="SELECT \\*"):
        await data.run_query(env["src"], "SELECT * FROM customers")
    ok = await data.run_query(env["src"], "SELECT * FROM orders LIMIT 2")
    assert ok["row_count"] == 2


async def test_truncation_is_explicit_and_exact(env):
    r = await data.run_query(env["src"], "SELECT id FROM orders", max_rows=100)
    assert r["row_count"] == 100 and r["truncated"] is True
    assert "TRUNCATED" in r["warnings"][0]
    full = await data.run_query(env["src"], "SELECT id FROM orders", max_rows=5000)
    assert full["row_count"] == 1200 and full["truncated"] is False and not full["warnings"]
    exact = await data.run_query(env["src"], "SELECT id FROM orders", max_rows=1200)
    assert exact["row_count"] == 1200 and exact["truncated"] is False  # boundary case


async def test_aggregates_are_exact(env):
    r = await data.run_query(env["src"], "SELECT COUNT(*) n, SUM(amount) s FROM orders")
    assert r["rows"][0][0] == 1200
    assert r["columns"][0]["name"] == "n"


async def test_write_queries_rejected_and_audited(env):
    for q in ["DELETE FROM orders", "DROP TABLE orders", "SELECT 1; DELETE FROM orders"]:
        with pytest.raises(ValueError):
            await data.run_query(env["src"], q)
    r = await data.run_query(env["src"], "SELECT COUNT(*) FROM orders")
    assert r["rows"][0][0] == 1200  # nothing was deleted
    async with SessionLocal() as s:
        logs = (await s.execute(select(AuditLog))).scalars().all()
    assert sum(l.status == "rejected" for l in logs) == 3
    assert any(l.status == "ok" for l in logs)


async def test_unknown_table_suggests_names(env):
    with pytest.raises(ValueError, match="Did you mean.*orders"):
        await data.run_query(env["src"], "SELECT * FROM order")


async def test_db_error_is_clean(env):
    with pytest.raises(ValueError, match="Database error"):
        await data.run_query(env["src"], "SELECT nope FROM orders")


async def test_search_schema(env):
    r = await data.search_schema(env["src"], "amount")
    assert r["matches"][0]["table"] in ("orders", "big_orders")
    assert "amount" in r["matches"][0]["matching_columns"]


async def test_tenant_isolation(env):
    current_user_id.set(env["b"])
    assert await list_data_sources() == []
    for call in (data.get_schema_overview(env["src"]),
                 data.run_query(env["src"], "SELECT 1"),
                 data.describe_table(env["src"], "orders")):
        with pytest.raises(ValueError, match="not found"):
            await call
    async with SessionLocal() as s:
        assert await service.get_owned(s, env["b"], env["src"]) is None
        assert await service.delete_source(s, env["b"], env["src"]) is False
    current_user_id.set(env["a"])
    assert len(await list_data_sources()) == 1


async def test_credentials_encrypted_at_rest(env):
    async with SessionLocal() as s:
        src = await s.get(DataSource, env["src"])
    assert str(env["path"]).encode() not in src.config_encrypted
    assert decrypt_config(src.config_encrypted, src.id)["database"] == str(env["path"])
    with pytest.raises(Exception):  # blob is bound to its source id
        decrypt_config(src.config_encrypted, "someone-else")


async def test_connector_enforces_readonly_even_if_guard_bypassed(env):
    conn = service.connector_for(await _src(env))
    with pytest.raises(Exception):
        await conn.execute("DELETE FROM orders", 10, 5)


async def test_query_timeout(env):
    conn = service.connector_for(await _src(env))
    slow = ("WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) "
            "SELECT COUNT(*) FROM r")
    with pytest.raises(Exception):
        await conn.execute(slow, 10, 1)


async def test_duplicate_name_and_bad_connection(env):
    async with SessionLocal() as s:
        with pytest.raises(service.SourceError, match="already have"):
            await service.create_source(s, env["a"], "Shop", "sqlite", {"database": "x"})
        with pytest.raises(service.SourceError, match="Connection failed"):
            await service.create_source(s, env["a"], "Bad", "sqlite",
                                        {"database": "/nonexistent/dir/x.db"})


async def _src(env):
    async with SessionLocal() as s:
        return await s.get(DataSource, env["src"])


def test_crypto_roundtrip_and_tamper():
    blob = encrypt_config({"password": "p@ss"}, "id1")
    assert b"p@ss" not in blob
    assert decrypt_config(blob, "id1") == {"password": "p@ss"}
    with pytest.raises(Exception):
        decrypt_config(blob[:-1] + bytes([blob[-1] ^ 1]), "id1")


@pytest.mark.parametrize("host", ["169.254.169.254", "0.0.0.0", "224.0.0.1"])
def test_ssrf_blocked_ranges(host):
    with pytest.raises(HostBlocked):
        check_host(host)


def test_loopback_blocked_by_default():
    with pytest.raises(HostBlocked):
        check_host("127.0.0.1")
    check_host("10.1.2.3")  # private LAN is allowed
