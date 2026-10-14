"""Personal API tokens: service rules and the web UI."""
import html
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select, text

from app.auth import api_tokens
from app.auth.passwords import hash_password
from app.auth.tokens import sha256
from app.db.models import ApiToken, AuditLog, Base, User
from app.db.session import SessionLocal, engine
from app.main import app

PW = "pw12345678!"


@pytest_asyncio.fixture
async def env():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as s:
        a = User(email="a@x.in", name="A", password_hash=hash_password(PW), must_change_password=False)
        b = User(email="b@x.in", name="B", password_hash=hash_password(PW), must_change_password=False)
        s.add_all([a, b])
        await s.commit()
    yield {"a": a.id, "b": b.id}


async def owner(uid):
    async with SessionLocal() as s:
        return await s.get(User, uid)


async def create(uid, name="t", provider="openai", days=30):
    async with SessionLocal() as s:
        return await api_tokens.create_token(s, await s.get(User, uid), name, provider, days)


# ------------------------------------------------------------------ service
async def test_token_format_and_it_is_stored_only_as_a_hash(env):
    plain, row = await create(env["a"])
    assert plain.startswith("mk_") and len(plain) >= 40
    assert row.token_hash == sha256(plain) and row.prefix == plain[:8]
    async with SessionLocal() as s:                       # nothing in the table holds the secret
        dump = " ".join(str(v) for r in (await s.execute(text("SELECT * FROM api_tokens"))).all() for v in r)
    assert plain not in dump and plain[3:] not in dump
    p2, _ = await create(env["a"])
    assert p2 != plain                                    # random


async def test_expiry_is_mandatory_and_bounded(env):
    for days in (0, 1, 7, 91, 10_000, -5):
        with pytest.raises(api_tokens.TokenError, match="Lifetime"):
            await create(env["a"], days=days)
    for days in api_tokens.LIFETIMES_DAYS:
        _, row = await create(env["a"], name=f"d{days}", days=days)
        left = (row.expires_at.replace(tzinfo=timezone.utc) if row.expires_at.tzinfo is None
                else row.expires_at) - datetime.now(timezone.utc)
        assert timedelta(days=days) - timedelta(minutes=1) < left <= timedelta(days=days)


async def test_input_validation(env):
    for name in ("", "   ", "x" * 81):
        with pytest.raises(api_tokens.TokenError, match="name"):
            await create(env["a"], name=name)
    with pytest.raises(api_tokens.TokenError, match="which app"):
        await create(env["a"], provider="skynet")
    plain, row = await create(env["a"], name="  padded  ")
    assert row.name == "padded"


async def test_at_most_ten_active_tokens_and_revoked_or_expired_do_not_count(env):
    made = [await create(env["a"], name=f"t{i}") for i in range(10)]
    with pytest.raises(api_tokens.TokenError, match="10 active"):
        await create(env["a"], name="eleventh")
    async with SessionLocal() as s:                       # revoke one, expire another
        assert await api_tokens.revoke_token(s, env["a"], made[0][1].id)
        r = await s.get(ApiToken, made[1][1].id)
        r.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        await s.commit()
    await create(env["a"], name="slot-1")
    await create(env["a"], name="slot-2")
    with pytest.raises(api_tokens.TokenError, match="10 active"):
        await create(env["a"], name="again")
    await create(env["b"], name="other user is unaffected")


async def test_authenticate_rules(env):
    plain, row = await create(env["a"], provider="gemini")
    async with SessionLocal() as s:
        user, tok = await api_tokens.authenticate_token(s, plain)
        assert user.id == env["a"] and tok.provider == "gemini"
        for bad in ("", "mk_", "mk_" + "x" * 43, plain + "x", plain[:-1], "Bearer " + plain,
                    plain.replace("mk_", "xx_", 1), "x" * 200):
            assert await api_tokens.authenticate_token(s, bad) is None, bad


async def test_last_used_is_updated_but_not_on_every_call(env):
    plain, row = await create(env["a"])
    async with SessionLocal() as s:
        assert (await s.get(ApiToken, row.id)).last_used_at is None
        await api_tokens.authenticate_token(s, plain)
        first = (await s.get(ApiToken, row.id)).last_used_at
        assert first is not None
        await api_tokens.authenticate_token(s, plain)               # within 5 minutes
        assert (await s.get(ApiToken, row.id)).last_used_at == first
        (await s.get(ApiToken, row.id)).last_used_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        await s.commit()
        await api_tokens.authenticate_token(s, plain)
        assert (await s.get(ApiToken, row.id)).last_used_at > first - timedelta(minutes=1)


async def test_revoke_is_owner_scoped(env):
    _, row = await create(env["a"])
    async with SessionLocal() as s:
        assert await api_tokens.revoke_token(s, env["b"], row.id) is False   # not B's token
        assert await api_tokens.revoke_token(s, env["a"], "nope") is False
        assert await api_tokens.revoke_token(s, env["a"], row.id) is True
        assert (await s.get(ApiToken, row.id)).revoked is True


# ------------------------------------------------------------------ web UI
def csrf_of(page):
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


async def login(email):
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    r = await c.post("/login", data={"email": email, "password": PW})
    assert r.status_code == 303
    return c


async def test_ui_requires_login(env):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        for method, url in (("get", "/account/tokens"), ("post", "/account/tokens")):
            r = await getattr(c, method)(url)
            assert r.status_code in (303, 422)
        assert (await c.get("/account/tokens")).headers["location"] == "/login"


async def test_ui_create_shows_secret_once_with_ready_to_paste_config(env):
    c = await login("a@x.in")
    try:
        csrf = csrf_of((await c.get("/account/tokens")).text)
        r = await c.post("/account/tokens", data={"name": "my openai", "provider": "openai",
                                                  "days": "90", "csrf": csrf})
        body = html.unescape(r.text)
        token = re.search(r"mk_[A-Za-z0-9_-]{30,}", body).group(0)
        assert "shown only once" in body and "Copy it now" in body
        assert '"type": "mcp"' in body and '"server_url": "http://test/mcp"' in body
        assert f'"authorization": "{token}"' in body and '"require_approval": "always"' in body
        again = html.unescape((await c.get("/account/tokens")).text)
        assert token not in again and token[:8] in again and "my openai" in again   # prefix only
        gem = html.unescape((await c.post("/account/tokens", data={
            "name": "gem", "provider": "gemini", "days": "30", "csrf": csrf})).text)
        assert '"httpUrl": "http://test/mcp"' in gem and "Authorization" in gem and "Bearer mk_" in gem
        other = html.unescape((await c.post("/account/tokens", data={
            "name": "misc", "provider": "other", "days": "365", "csrf": csrf})).text)
        assert "Header: Authorization: Bearer mk_" in other
    finally:
        await c.aclose()


async def test_ui_audit_trail_never_contains_the_secret(env):
    c = await login("a@x.in")
    try:
        csrf = csrf_of((await c.get("/account/tokens")).text)
        r = await c.post("/account/tokens", data={"name": "n", "provider": "gemini", "days": "30",
                                                  "csrf": csrf})
        token = re.search(r"mk_[A-Za-z0-9_-]{30,}", html.unescape(r.text)).group(0)
    finally:
        await c.aclose()
    async with SessionLocal() as s:
        rows = (await s.execute(select(AuditLog).where(AuditLog.tool == "ui:create_api_token"))).scalars().all()
    assert len(rows) == 1 and rows[0].provider == "gemini" and rows[0].user_id == env["a"]
    assert token not in (rows[0].sql_text or "") and token[:8] in rows[0].sql_text


async def test_ui_validation_errors_csrf_and_limit(env):
    c = await login("a@x.in")
    try:
        csrf = csrf_of((await c.get("/account/tokens")).text)
        r = await c.post("/account/tokens", data={"name": "", "provider": "openai", "days": "30", "csrf": csrf})
        assert "Give the token a name" in r.text
        r = await c.post("/account/tokens", data={"name": "x", "provider": "openai", "days": "7", "csrf": csrf})
        assert "Lifetime" in r.text
        r = await c.post("/account/tokens", data={"name": "x", "provider": "bogus", "days": "30", "csrf": csrf})
        assert "Choose which app" in r.text
        r = await c.post("/account/tokens", data={"name": "x", "provider": "openai", "days": "30", "csrf": "forged"})
        assert r.status_code == 403
        for i in range(10):
            await c.post("/account/tokens", data={"name": f"t{i}", "provider": "other", "days": "30", "csrf": csrf})
        r = await c.post("/account/tokens", data={"name": "one too many", "provider": "other",
                                                  "days": "30", "csrf": csrf})
        assert "10 active tokens" in r.text and "one too many" not in r.text
    finally:
        await c.aclose()


async def test_ui_revoke_works_and_is_owner_scoped(env):
    plain, row = await create(env["a"], name="to revoke")
    ca, cb = await login("a@x.in"), await login("b@x.in")
    try:
        bcsrf = csrf_of((await cb.get("/account/tokens")).text)
        assert (await cb.post(f"/account/tokens/{row.id}/revoke", data={"csrf": bcsrf})).status_code == 404
        async with SessionLocal() as s:
            assert await api_tokens.authenticate_token(s, plain) is not None     # still alive
        acsrf = csrf_of((await ca.get("/account/tokens")).text)
        assert (await ca.post(f"/account/tokens/{row.id}/revoke", data={"csrf": "forged"})).status_code == 403
        page = await ca.post(f"/account/tokens/{row.id}/revoke", data={"csrf": acsrf})
        assert page.status_code == 200 and "(revoked)" in page.text
        async with SessionLocal() as s:
            assert await api_tokens.authenticate_token(s, plain) is None
    finally:
        await ca.aclose()
        await cb.aclose()
