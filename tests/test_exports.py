import csv
import hashlib
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import httpx
import jwt
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.auth.passwords import hash_password
from app.config import get_settings
from app.db.models import AuditLog, Base, Export, User
from app.db.session import SessionLocal, engine
from app.exports import service as exports_svc
from app.main import app
from app.mcp_tools import exports as tools
from app.mcp_tools.server import current_user_id
from app.sources import service

N = 3000


class Up:
    def __init__(self, b):
        self._b = io.BytesIO(b)

    async def read(self, n=-1):
        return self._b.read(n)


@pytest_asyncio.fixture(params=["sqlite", "files"])
async def env(request, tmp_path):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    rows = [(i, f"{i:05d}", f"{Decimal(i) * Decimal('1.10'):.2f}", "2026-01-01",
             "a,b \"q\"\nline" if i % 500 == 0 else f"n{i}") for i in range(1, N + 1)]
    async with SessionLocal() as s:
        u = User(email="e@x.in", name="E", password_hash=hash_password("x"))
        o = User(email="o@x.in", name="O", password_hash=hash_password("x"))
        s.add_all([u, o])
        await s.commit()
        if request.param == "sqlite":
            p = tmp_path / "e.db"
            db = sqlite3.connect(p)
            db.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, code TEXT, amount NUMERIC, "
                       "d TEXT, note TEXT, phone TEXT)")
            db.executemany("INSERT INTO t VALUES (?,?,?,?,?,'999')", rows)
            db.commit(); db.close()
            src = await service.create_source(s, u.id, "e", "sqlite", {"database": str(p)})
        else:
            lines = ["id,code,amount,d,note,phone"] + [
                ",".join([str(r[0]), r[1], r[2], r[3], '"' + r[4].replace('"', '""') + '"', "999"])
                for r in rows]
            src = await service.create_file_source(s, u.id, "e", [
                ("t.csv", Up(("\n".join(lines) + "\n").encode()))])
        src.masked_columns = ["phone"]
        await s.commit()
    current_user_id.set(u.id)
    yield {"src": src.id, "engine": request.param, "user": u.id, "other": o.id, "rows": rows}


def read_csv_file(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.reader(f))


async def test_export_is_complete_exact_and_verifiable(env):
    m = await tools.export_result(env["src"], "SELECT id, code, amount, note FROM t ORDER BY id")
    assert m["rows"] == N                               # run_query would cap at 500
    async with SessionLocal() as s:
        e = await s.get(Export, m["export_id"])
    data = read_csv_file(e.path)
    assert data[0] == ["id", "code", "amount", "note"] and len(data) == N + 1
    assert hashlib.sha256(Path(e.path).read_bytes()).hexdigest() == m["sha256"]
    assert m["size_bytes"] == Path(e.path).stat().st_size
    assert data[1][1] == "00001"                        # leading zeros intact
    assert Decimal(data[N][2]) == Decimal(N) * Decimal("1.10")
    assert sum(Decimal(r[2]) for r in data[1:]) == sum(Decimal(r[2]) for r in env["rows"])
    assert data[500][3] == 'a,b "q"\nline'              # quoting / embedded newline round-trips
    assert [c["name"] for c in m["columns"]] == ["id", "code", "amount", "note"]
    assert m["download_url"].startswith("http://test/files/")


async def test_export_enforces_same_safety_as_run_query(env):
    for q in ("DELETE FROM t", "SELECT phone FROM t", "SELECT * FROM t",
              "SELECT 1; SELECT 2", "SELECT * FROM nope"):
        with pytest.raises(ValueError):
            await tools.export_result(env["src"], q)
    async with SessionLocal() as s:
        assert (await s.execute(select(Export))).first() is None   # nothing was created
        statuses = {l.status for l in (await s.execute(select(AuditLog))).scalars()}
    assert "rejected" in statuses and not list(
        (Path(get_settings().data_dir) / "exports" / env["user"]).glob("*.csv"))


async def test_export_over_row_cap_fails_and_leaves_nothing(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "export_max_rows", 100)
    with pytest.raises(ValueError, match="exceeds the export limit"):
        await tools.export_result(env["src"], "SELECT id FROM t")
    folder = Path(get_settings().data_dir) / "exports" / env["user"]
    assert not list(folder.glob("*.csv")) if folder.exists() else True
    async with SessionLocal() as s:
        assert (await s.execute(select(Export))).first() is None


async def test_export_size_cap(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "export_max_mb", 0)
    with pytest.raises(ValueError, match="larger than"):
        await tools.export_result(env["src"], "SELECT id FROM t")
    folder = Path(get_settings().data_dir) / "exports" / env["user"]
    assert not list(folder.glob("*.csv")) if folder.exists() else True


async def test_signed_download_roundtrip_and_headers(env):
    m = await tools.export_result(env["src"], "SELECT id, code FROM t")
    token = m["download_url"].rsplit("/", 1)[1]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as c:
        r = await c.get(f"/files/{token}")
        assert r.status_code == 200 and r.headers["x-export-sha256"] == m["sha256"]
        assert hashlib.sha256(r.content).hexdigest() == m["sha256"]
        assert r.headers["cache-control"] == "no-store"
        assert (await c.get(f"/files/{token}x")).status_code == 403      # tampered
        assert (await c.get("/files/garbage")).status_code == 403
        expired = jwt.encode({"sub": m["export_id"], "uid": env["user"], "aud": "download",
                              "exp": int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp())},
                             get_settings().jwt_secret, algorithm="HS256")
        assert (await c.get(f"/files/{expired}")).status_code == 403
        wrong_aud = jwt.encode({"sub": m["export_id"], "uid": env["user"], "aud": "mcp",
                                "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())},
                               get_settings().jwt_secret, algorithm="HS256")
        assert (await c.get(f"/files/{wrong_aud}")).status_code == 403
        forged = jwt.encode({"sub": m["export_id"], "uid": env["other"], "aud": "download",
                             "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())},
                            get_settings().jwt_secret, algorithm="HS256")
        assert (await c.get(f"/files/{forged}")).status_code == 404     # not that user's export
        async with SessionLocal() as s:                                 # disabling the user cuts access
            u = await s.get(User, env["user"])
            u.is_active = False
            await s.commit()
        assert (await c.get(f"/files/{token}")).status_code == 404


async def test_exports_are_owner_scoped_and_relinkable(env):
    m = await tools.export_result(env["src"], "SELECT id FROM t")
    again = await tools.get_export_link(m["export_id"])
    assert again["sha256"] == m["sha256"] and again["download_url"]
    assert [x["export_id"] for x in (await tools.list_exports())["exports"]] == [m["export_id"]]
    assert "download_url" not in (await tools.list_exports())["exports"][0]
    current_user_id.set(env["other"])
    with pytest.raises(ValueError, match="not found"):
        await tools.get_export_link(m["export_id"])
    assert (await tools.list_exports())["exports"] == []
    with pytest.raises(ValueError, match="not found"):
        await tools.export_result(env["src"], "SELECT id FROM t")


async def test_purge_expired_removes_files_and_rows(env):
    m = await tools.export_result(env["src"], "SELECT id FROM t")
    keep = await tools.export_result(env["src"], "SELECT id FROM t WHERE id < 5")
    async with SessionLocal() as s:
        e = await s.get(Export, m["export_id"])
        e.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        path = e.path
        await s.commit()
    assert await exports_svc.purge_expired() == 1
    assert not Path(path).exists()
    with pytest.raises(ValueError, match="not found or expired"):
        await tools.get_export_link(m["export_id"])
    assert (await tools.get_export_link(keep["export_id"]))["rows"] == 4


async def test_concurrent_export_refused(env):
    import asyncio
    exports_svc._LOCKS.setdefault(env["user"], asyncio.Lock())
    async with exports_svc._LOCKS[env["user"]]:
        with pytest.raises(ValueError, match="already have an export running"):
            await tools.export_result(env["src"], "SELECT id FROM t")
