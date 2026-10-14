import re

import httpx
import pytest
import pytest_asyncio

from app.auth.passwords import hash_password
from app.db.models import Base, User
from app.db.session import SessionLocal, engine
from app.main import app

PW = "pw12345678!"


async def _add(email, role="analyst", must_change=False):
    async with SessionLocal() as s:
        s.add(User(email=email, name=email.split("@")[0], role=role,
                   password_hash=hash_password(PW), must_change_password=must_change))
        await s.commit()


@pytest_asyncio.fixture
async def make_client():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    await _add("admin@medkart.in", "admin")
    await _add("analyst@medkart.in")
    clients = []

    def make():
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
        clients.append(c)
        return c

    yield make
    for c in clients:
        await c.aclose()


async def _login(c, email, password=PW):
    return await c.post("/login", data={"email": email, "password": password})


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


async def test_anonymous_is_redirected(make_client):
    r = await make_client().get("/admin/users")
    assert r.status_code == 303 and r.headers["location"] == "/login"


async def test_login_failure_and_success(make_client):
    c = make_client()
    r = await _login(c, "admin@medkart.in", "wrong")
    assert r.status_code == 200 and "Invalid" in r.text
    r = await _login(c, "admin@medkart.in")
    assert r.status_code == 303
    page = await c.get("/admin/users")
    assert page.status_code == 200 and "Create user" in page.text


async def test_admin_creates_user_and_new_user_must_change_password(make_client):
    admin = make_client()
    await _login(admin, "admin@medkart.in")
    page = await admin.get("/admin/users")
    r = await admin.post("/admin/users", data={
        "email": "New@Medkart.in", "name": "New", "role": "analyst", "csrf": _csrf(page.text)})
    assert r.status_code == 200
    temp = re.search(r"shown once\): ([\w-]+)", r.text).group(1)

    user = make_client()
    assert (await _login(user, "new@medkart.in", temp)).status_code == 303
    r = await user.get("/admin/users")
    assert r.status_code == 303 and r.headers["location"] == "/account/password"
    form = await user.get("/account/password")
    r = await user.post("/account/password", data={
        "current": temp, "new": "short", "csrf": _csrf(form.text)})
    assert "at least" in r.text
    r = await user.post("/account/password", data={
        "current": temp, "new": "a-much-longer-pass", "csrf": _csrf(form.text)})
    assert r.status_code == 303
    assert (await user.get("/admin/users")).status_code == 200  # no more forced redirect


async def test_duplicate_email_rejected(make_client):
    admin = make_client()
    await _login(admin, "admin@medkart.in")
    csrf = _csrf((await admin.get("/admin/users")).text)
    r = await admin.post("/admin/users", data={
        "email": "analyst@medkart.in", "name": "Dup", "role": "analyst", "csrf": csrf})
    assert "already exists" in r.text


async def test_csrf_enforced(make_client):
    admin = make_client()
    await _login(admin, "admin@medkart.in")
    r = await admin.post("/admin/users", data={
        "email": "x@medkart.in", "name": "X", "role": "analyst", "csrf": "forged"})
    assert r.status_code == 403


async def test_analyst_cannot_administer(make_client):
    a = make_client()
    await _login(a, "analyst@medkart.in")
    page = await a.get("/admin/users")
    assert "Create user" not in page.text
    r = await a.post("/admin/users", data={
        "email": "x@medkart.in", "name": "X", "role": "admin", "csrf": _csrf(page.text)})
    assert r.status_code == 403


async def test_disable_blocks_login_and_self_disable_refused(make_client):
    admin = make_client()
    await _login(admin, "admin@medkart.in")
    page = await admin.get("/admin/users")
    csrf = _csrf(page.text)
    async with SessionLocal() as s:
        from sqlalchemy import select
        users = {u.email: u.id for u in (await s.execute(select(User))).scalars()}
    r = await admin.post(f"/admin/users/{users['admin@medkart.in']}/toggle", data={"csrf": csrf})
    assert "cannot disable your own" in r.text
    r = await admin.post(f"/admin/users/{users['analyst@medkart.in']}/toggle", data={"csrf": csrf})
    assert r.status_code == 303
    r = await _login(make_client(), "analyst@medkart.in")
    assert r.status_code == 200 and "Invalid" in r.text


async def test_user_adds_source_via_ui_and_sees_only_own(make_client, tmp_path):
    import sqlite3
    path = tmp_path / "ui.db"
    conn = sqlite3.connect(path); conn.execute("CREATE TABLE t(a)"); conn.commit(); conn.close()
    a = make_client(); await _login(a, "analyst@medkart.in")
    csrf = _csrf((await a.get("/sources")).text)
    bad = await a.post("/sources", data={"name": "X", "engine": "sqlite", "database": "",
                                         "csrf": csrf})
    assert "required" in bad.text
    r = await a.post("/sources", data={"name": "Mine", "engine": "sqlite",
                                       "database": str(path), "password": "secret-pw",
                                       "csrf": csrf})
    assert "Connected" in r.text and "secret-pw" not in r.text
    assert "Mine" in (await a.get("/sources")).text
    other = make_client(); await _login(other, "admin@medkart.in")
    assert "Mine" not in (await other.get("/sources")).text
    async with SessionLocal() as s:
        from sqlalchemy import select
        from app.db.models import DataSource
        sid = (await s.execute(select(DataSource.id))).scalar_one()
    ocsrf = _csrf((await other.get("/sources")).text)
    assert (await other.post(f"/sources/{sid}/delete", data={"csrf": ocsrf})).status_code == 404
    assert (await other.post(f"/sources/{sid}/masked",
                             data={"csrf": ocsrf, "columns": "x"})).status_code == 404


async def test_file_upload_through_ui(make_client):
    c = make_client()
    await _login(c, "analyst@medkart.in")
    csrf = _csrf((await c.get("/sources")).text)
    r = await c.post("/sources/upload", data={"name": "Uploaded", "csrf": csrf},
                     files=[("files", ("my data.csv", b"id,code\n1,007\n2,008\n", "text/csv"))])
    assert r.status_code == 200 and "Loaded" in r.text and "1 table" in r.text
    bad = await c.post("/sources/upload", data={"name": "Bad", "csrf": csrf},
                       files=[("files", ("evil.exe", b"MZ", "application/octet-stream"))])
    assert "only .csv" in bad.text
    forged = await c.post("/sources/upload", data={"name": "X", "csrf": "forged"},
                          files=[("files", ("a.csv", b"a\n1\n", "text/csv"))])
    assert forged.status_code == 403


async def test_admin_audit_page_access_filters_and_escaping(make_client):
    from app.audit.logger import audit
    async with SessionLocal() as s:
        from sqlalchemy import select
        from app.db.models import User as U
        uid = (await s.execute(select(U.id).where(U.email == "analyst@medkart.in"))).scalar_one()
    await audit(user_id=uid, tool="run_query", status="ok", sql="SELECT 1", row_count=1,
                elapsed_ms=5)
    await audit(user_id=uid, tool="run_query", status="rejected",
                sql="SELECT '<script>alert(1)</script>'", error="nope <b>x</b>")
    a = make_client(); await _login(a, "analyst@medkart.in")
    assert (await a.get("/admin/audit")).status_code == 403          # analysts cannot view
    adm = make_client(); await _login(adm, "admin@medkart.in")
    page = await adm.get("/admin/audit")
    assert page.status_code == 200 and "SELECT 1" in page.text and "analyst@medkart.in" in page.text
    assert "<script>alert(1)</script>" not in page.text              # escaped, not executed
    assert "&lt;script&gt;" in page.text
    only = await adm.get("/admin/audit?status=rejected")
    assert "SELECT 1<" not in only.text and "rejected" in only.text
    assert "analyst@medkart.in" in (await adm.get("/admin/audit?user=ANALYST@medkart.in")).text
    nobody = await adm.get("/admin/audit?user=ghost@x.in")
    assert "No matching events" in nobody.text
    anon = make_client()
    assert (await anon.get("/admin/audit")).status_code == 303       # not logged in
