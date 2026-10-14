import logging

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app.auth.passwords import hash_password, verify_password
from app.bootstrap import ensure_bootstrap_admin
from app.config import get_settings
from app.db.models import Base, User
from app.db.session import SessionLocal, engine
from app.main import app

PW = "Bootstrap-Pass-123"


@pytest_asyncio.fixture
async def empty_db():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)


def configure(monkeypatch, email="Boss@Medkart.in", password=PW, name="Boss"):
    s = get_settings()
    monkeypatch.setattr(s, "bootstrap_admin_email", email)
    monkeypatch.setattr(s, "bootstrap_admin_password", password)
    monkeypatch.setattr(s, "bootstrap_admin_name", name)


async def users():
    async with SessionLocal() as db:
        return (await db.execute(select(User))).scalars().all()


async def test_noop_when_not_configured(empty_db, monkeypatch):
    configure(monkeypatch, "", "")
    assert await ensure_bootstrap_admin() is False
    assert await users() == []


async def test_creates_admin_that_must_change_password(empty_db, monkeypatch):
    configure(monkeypatch)
    assert await ensure_bootstrap_admin() is True
    [u] = await users()
    assert u.email == "boss@medkart.in" and u.name == "Boss"      # normalised email
    assert u.role == "admin" and u.is_active and u.must_change_password
    assert u.password_hash.startswith("$argon2") and verify_password(PW, u.password_hash)
    assert PW not in u.password_hash


async def test_can_sign_in_then_is_forced_to_change_password(empty_db, monkeypatch):
    configure(monkeypatch)
    await ensure_bootstrap_admin()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as c:
        assert (await c.post("/login", data={"email": "boss@medkart.in",
                                             "password": PW})).status_code == 303
        r = await c.get("/admin/users")
        assert r.status_code == 303 and r.headers["location"] == "/account/password"


async def test_never_runs_twice_and_never_resets_a_changed_password(empty_db, monkeypatch):
    configure(monkeypatch)
    await ensure_bootstrap_admin()
    async with SessionLocal() as db:                     # the admin sets their own password
        u = (await db.execute(select(User))).scalar_one()
        u.password_hash, u.must_change_password = hash_password("my-own-new-password"), False
        await db.commit()
    assert await ensure_bootstrap_admin() is False       # e.g. server restart
    [u] = await users()
    assert verify_password("my-own-new-password", u.password_hash)
    assert not verify_password(PW, u.password_hash)      # env password is dead
    assert u.must_change_password is False


async def test_skipped_when_any_user_exists(empty_db, monkeypatch):
    async with SessionLocal() as db:
        db.add(User(email="someone@x.in", name="S", password_hash=hash_password("x" * 12)))
        await db.commit()
    configure(monkeypatch)
    assert await ensure_bootstrap_admin() is False
    assert [x.email for x in await users()] == ["someone@x.in"]   # no second admin appeared


async def test_a_deleted_or_disabled_admin_is_not_resurrected_via_env(empty_db, monkeypatch):
    configure(monkeypatch)
    await ensure_bootstrap_admin()
    async with SessionLocal() as db:
        u = (await db.execute(select(User))).scalar_one()
        u.is_active = False
        await db.commit()
    assert await ensure_bootstrap_admin() is False
    assert (await users())[0].is_active is False


@pytest.mark.parametrize("email,password,msg", [
    ("not-an-email", PW, "EMAIL"),
    ("a@b", PW, "EMAIL"),
    ("boss@medkart.in", "short", "at least 10"),
    ("boss@medkart.in", "", "at least 10"),     # email set but password missing
    ("", PW, "EMAIL"),                          # password set but email missing
])
async def test_bad_configuration_fails_fast_and_creates_nothing(empty_db, monkeypatch, email,
                                                                 password, msg):
    configure(monkeypatch, email, password)
    with pytest.raises(RuntimeError, match=msg):
        await ensure_bootstrap_admin()
    assert await users() == []


async def test_clear_error_when_database_not_migrated(monkeypatch):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)           # no tables at all
    configure(monkeypatch)
    with pytest.raises(RuntimeError, match="migrate"):
        await ensure_bootstrap_admin()


async def test_password_is_never_logged(empty_db, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    configure(monkeypatch)
    await ensure_bootstrap_admin()
    blob = " ".join(str(r.__dict__) + r.getMessage() for r in caplog.records)
    assert PW not in blob and "bootstrap_admin_created" in blob


async def test_runs_automatically_at_server_start(empty_db, monkeypatch):
    # The MCP session manager may only be started once per process, so stand it in; the rest of
    # the real startup path (secret checks, bootstrap, maintenance task) is exercised.
    from contextlib import asynccontextmanager

    class _Manager:
        @asynccontextmanager
        async def run(self):
            yield

    class _Mcp:
        session_manager = _Manager()

    monkeypatch.setattr("app.main.mcp", _Mcp())
    configure(monkeypatch)
    async with app.router.lifespan_context(app):
        pass
    assert [u.email for u in await users()] == ["boss@medkart.in"]
    async with app.router.lifespan_context(app):          # restart: still exactly one user
        pass
    assert len(await users()) == 1


async def test_bad_bootstrap_config_stops_the_server_from_starting(empty_db, monkeypatch):
    configure(monkeypatch, "boss@medkart.in", "short")
    with pytest.raises(RuntimeError, match="at least 10"):
        async with app.router.lifespan_context(app):
            pass
