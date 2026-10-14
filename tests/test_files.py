import io
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import openpyxl
import pytest
import pytest_asyncio

from app.auth.passwords import hash_password
from app.config import get_settings
from app.connectors import registry
from app.db.models import Base, DataSource, User
from app.db.session import SessionLocal, engine
from app.mcp_tools import data
from app.mcp_tools.server import current_user_id
from app.sources import service


class Up:
    """Minimal async upload stand-in."""
    def __init__(self, content: bytes):
        self._b = io.BytesIO(content)

    async def read(self, n=-1):
        return self._b.read(n)


SALES = (
    "sku,batch,qty,price,sold_on,note\n"
    "A1,00123,5,10.10,2026-01-05,ok\n"
    "A2,00456,3,20.20,2026-01-06,\n"
    "A3,00789,2,30.30,2026-01-07,late\n"
).encode()


def make_xlsx() -> bytes:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Stock"
    ws.append([])                       # blank row above the header
    ws.append(["item", "units", "cost", "received"])
    ws.append(["x", 10.0, 1.25, datetime(2026, 2, 1)])
    ws.append(["y", 20.0, 2.5, datetime(2026, 2, 2, 13, 30)])
    wb.create_sheet("Empty")
    b = io.BytesIO()
    wb.save(b)
    return b.getvalue()


@pytest_asyncio.fixture
async def env():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as s:
        a = User(email="f@x.in", name="F", password_hash=hash_password("x"))
        b = User(email="g@x.in", name="G", password_hash=hash_password("x"))
        s.add_all([a, b])
        await s.commit()
        src = await service.create_file_source(s, a.id, "Files", [
            ("Sales Data.csv", Up(SALES)), ("stock.xlsx", Up(make_xlsx())),
            ("legacy.csv", Up("name,city\nJosé,Zürich\nRenée,Köln\n".encode("latin-1")))])
    current_user_id.set(a.id)
    yield {"a": a.id, "b": b.id, "src": src.id}


def _types(d):
    return {c["name"]: c["type"] for c in d["columns"]}


async def _conn(env):
    async with SessionLocal() as s:
        return service.connector_for(await s.get(DataSource, env["src"]))


async def test_tables_created_from_csv_and_each_sheet(env):
    ov = await data.get_schema_overview(env["src"])
    names = {t["table"]: t for t in ov["tables"]}
    assert set(names) == {"sales_data", "stock_stock", "legacy"}   # empty sheet skipped
    assert names["sales_data"]["rows"] == 3 and names["stock_stock"]["rows"] == 2


async def test_type_inference_is_strict(env):
    d = await data.describe_table(env["src"], "sales_data")
    t = _types(d)
    assert t["batch"] == "VARCHAR"            # '00123' must NOT become 123
    assert t["qty"] == "BIGINT"
    assert t["price"].startswith("DECIMAL(28,2")
    assert t["sold_on"] == "DATE"
    assert any("batch" in n and "leading zeros" in n for n in d["data_notes"])


async def test_leading_zero_codes_preserved_and_money_exact(env):
    r = await data.run_query(env["src"], "SELECT batch FROM sales_data ORDER BY batch")
    assert [x[0] for x in r["rows"]] == ["00123", "00456", "00789"]
    r = await data.run_query(env["src"], "SELECT SUM(price) s, SUM(qty) q FROM sales_data")
    assert Decimal(r["rows"][0][0]) == Decimal("60.60") and int(r["rows"][0][1]) == 10
    r = await data.run_query(env["src"], "SELECT note FROM sales_data WHERE sku = 'A2'")
    assert r["rows"] == [[None]]               # empty cell is NULL, not ''


async def test_excel_header_detection_and_value_fidelity(env):
    d = await data.describe_table(env["src"], "stock_stock")
    t = _types(d)
    assert t["units"] == "BIGINT"              # 10.0 -> 10
    assert t["cost"].startswith("DECIMAL")
    assert t["received"] == "TIMESTAMP"
    r = await data.run_query(env["src"], "SELECT SUM(cost) FROM stock_stock")
    assert Decimal(r["rows"][0][0]) == Decimal("3.75")
    assert d["source_file"].startswith("stock.xlsx") and "Stock" in d["source_file"]


async def test_non_utf8_csv(env):
    r = await data.run_query(env["src"], "SELECT name, city FROM legacy ORDER BY name")
    assert r["rows"] == [["José", "Zürich"], ["Renée", "Köln"]]


async def test_non_iso_dates_stay_text_with_note(env):
    async with SessionLocal() as s:
        src = await service.create_file_source(s, env["b"], "dates", [
            ("d.csv", Up(b"id,d\n1,03/04/2026\n2,15/04/2026\n"))])
    current_user_id.set(env["b"])
    d = await data.describe_table(src.id, "d")
    assert _types(d)["d"] == "VARCHAR" and any("non-ISO" in n for n in d["data_notes"])


async def test_reading_other_files_is_blocked(env):
    secret = Path(get_settings().data_dir) / "secret.csv"
    secret.write_text("a\nTOP-SECRET\n")
    for q in (f"SELECT * FROM read_csv('{secret.as_posix()}')",
              f"SELECT * FROM '{secret.as_posix()}'",
              "SELECT * FROM glob('*')"):
        with pytest.raises(ValueError):
            await data.run_query(env["src"], q)
    # even if the guard were bypassed, DuckDB itself has external access disabled
    conn = await _conn(env)
    out = secret.parent / "out.csv"
    for q in (f"SELECT * FROM read_csv('{secret.as_posix()}')",
              f"COPY sales_data TO '{out.as_posix()}'"):
        with pytest.raises(Exception):
            await conn.execute(q, 10, 5)
    assert not out.exists()


async def test_database_is_read_only_and_timeout(env):
    conn = await _conn(env)
    with pytest.raises(Exception):
        await conn.execute("DELETE FROM sales_data", 10, 5)
    with pytest.raises(TimeoutError):
        await conn.execute("SELECT SUM(a.range * b.range) FROM range(100000) a, "
                           "range(100000) b", 10, 1)
    r = await data.run_query(env["src"], "SELECT COUNT(*) FROM sales_data")
    assert int(r["rows"][0][0]) == 3


async def test_truncation_flag_on_files(env):
    r = await data.run_query(env["src"], "SELECT * FROM sales_data", max_rows=2)
    assert r["row_count"] == 2 and r["truncated"]


async def test_upload_validation(env, monkeypatch):
    async with SessionLocal() as s:
        for files, msg in [([("x.exe", Up(b"MZ"))], "only .csv"),
                           ([("e.csv", Up(b""))], "empty"),
                           ([], "at least one")]:
            with pytest.raises(service.SourceError, match=msg):
                await service.create_file_source(s, env["b"], "n", files)
        await service.create_file_source(s, env["b"], "ok", [("Dup.csv", Up(b"a\n1\n"))])
        monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
        with pytest.raises(service.SourceError, match="exceeds"):
            await service.create_file_source(s, env["b"], "big", [
                ("big.csv", Up(b"a\n" + b"1\n" * (1024 * 1024)))])
        with pytest.raises(service.SourceError, match="Could not read Excel"):
            await service.create_file_source(s, env["b"], "bad", [
                ("bad.xlsx", Up(b"not really excel"))])
    # failed loads leave nothing on disk: only the successful "ok" source remains
    folders = [p for p in (Path(get_settings().data_dir) / env["b"]).glob("*") if p.is_dir()]
    assert len(folders) == 1


async def test_delete_removes_files_and_is_owner_scoped(env):
    folder = registry.source_dir(env["a"], env["src"])
    assert (folder / "data.duckdb").exists()
    async with SessionLocal() as s:
        assert await service.delete_source(s, env["b"], env["src"]) is False
        assert folder.exists()
        assert await service.delete_source(s, env["a"], env["src"]) is True
    assert not folder.exists()


async def test_hostile_csv_headers_cannot_inject_sql_or_break_loading(env):
    """Column names come from the uploaded file and are quoted into DuckDB SQL while loading."""
    header = ['we"ird', "x'y", 'a"; DROP TABLE staging; --', "id", "id", " ", "SELECT"]
    body = ",".join('"' + h.replace('"', '""') + '"' for h in header) + "\n1,2,3,4,5,6,7\n"
    async with SessionLocal() as s:
        src = await service.create_file_source(s, env["b"], "hostile", [
            ("weird.csv", Up(body.encode()))])
    current_user_id.set(env["b"])
    d = await data.describe_table(src.id, "weird")
    names = [c["name"] for c in d["columns"]]
    assert len(names) == 7 and len(set(names)) == 7                  # sanitised and de-duplicated
    assert all(n.replace("_", "").isalnum() for n in names), names   # nothing odd survives
    cols = ", ".join('"' + n + '"' for n in names)          # 'select' is a reserved word
    r = await data.run_query(src.id, f"SELECT {cols} FROM weird")
    assert r["rows"] == [[1, 2, 3, 4, 5, 6, 7]]
    # a hostile file NAME is replaced by a server-chosen one, and cannot escape the folder
    async with SessionLocal() as s:
        src2 = await service.create_file_source(s, env["b"], "hostile2", [
            ("../../evil name;.csv", Up(b"a\n1\n"))])
    folder = registry.source_dir(env["b"], src2.id)
    assert {p.name for p in folder.iterdir()} <= {"_evil_name_.csv", "data.duckdb"}
