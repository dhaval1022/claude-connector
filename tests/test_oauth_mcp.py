import asyncio
import base64
import hashlib
import os
import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio

os.environ.update({
    "CONNECTOR_DATABASE_URL": "sqlite+aiosqlite:///./test_connector.db",
    "CONNECTOR_JWT_SECRET": "test-secret-test-secret-test-secret-32",
    "CONNECTOR_PUBLIC_BASE_URL": "http://test",
})

from app.auth.passwords import hash_password  # noqa: E402
from app.db.models import Base, User  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
H = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


pytestmark = pytest.mark.asyncio(loop_scope="module")


async def _user(email):
    async with SessionLocal() as s:
        s.add(User(email=email, name="T", password_hash=hash_password("pw12345!")))
        await s.commit()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    # MCP session manager can only run once per process, so the app lives for the module.
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    for e in ("a@medkart.in", "b@medkart.in"):
        await _user(e)
    ready, stop = asyncio.Event(), asyncio.Event()

    async def run_lifespan():  # enter and exit in the same task (anyio requirement)
        async with app.router.lifespan_context(app):
            ready.set()
            await stop.wait()

    task = asyncio.create_task(run_lifespan())
    await ready.wait()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as c:
        yield c
    stop.set()
    await task


async def _login(c, password="pw12345!", email="a@medkart.in"):
    reg = (await c.post("/oauth/register", json={"redirect_uris": [REDIRECT]})).json()
    verifier = "v" * 64
    chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    r = await c.post("/oauth/authorize", data={
        "client_id": reg["client_id"], "redirect_uri": REDIRECT, "code_challenge": chal,
        "state": "xyz", "email": email, "password": password})
    return reg["client_id"], verifier, r


async def test_full_flow(client):
    assert (await client.post("/mcp/", json={}, headers=H)).status_code == 401
    cid, verifier, r = await _login(client)
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["state"] == ["xyz"]
    t = await client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": cid, "code": q["code"][0],
        "redirect_uri": REDIRECT, "code_verifier": verifier})
    assert t.status_code == 200, t.text
    tok = t.json()
    # code is single-use
    again = await client.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": cid, "code": q["code"][0],
        "redirect_uri": REDIRECT, "code_verifier": verifier})
    assert again.status_code == 400
    auth = {**H, "Authorization": f"Bearer {tok['access_token']}"}
    init = await client.post("/mcp/", headers=auth, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "1"}}})
    assert init.status_code == 200, init.text
    lst = await client.post("/mcp/", headers=auth, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    for name in ("list_data_sources", "get_schema_overview", "describe_table", "search_schema",
                 "run_query", "refresh_schema_cache", "profile_table", "profile_column",
                 "validate_result", "get_relationships", "compare_periods",
                 "detect_anomalies", "get_business_context", "save_business_context",
                 "delete_business_context", "export_result", "get_export_link",
                 "list_exports", "list_script_templates", "generate_analysis_script"):
        assert f'"name":"{name}"' in lst.text.replace(" ", ""), f"tool {name} not registered"
    call = await client.post("/mcp/", headers=auth, json={
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "list_data_sources", "arguments": {}}})
    assert call.status_code == 200 and "error" not in call.json()
    # refresh rotation + replay detection
    rt = tok["refresh_token"]
    r1 = await client.post("/oauth/token", data={
        "grant_type": "refresh_token", "client_id": cid, "refresh_token": rt})
    assert r1.status_code == 200
    r2 = await client.post("/oauth/token", data={
        "grant_type": "refresh_token", "client_id": cid, "refresh_token": rt})
    assert r2.status_code == 400


async def test_bad_password_and_lockout(client):
    for _ in range(5):
        _, _, r = await _login(client, "wrong", "b@medkart.in")
        assert r.status_code == 200 and "Invalid" in r.text
    _, _, r = await _login(client, email="b@medkart.in")  # correct password but now locked
    assert "locked" in r.text


async def test_rejects_foreign_redirect(client):
    r = await client.post("/oauth/register", json={"redirect_uris": ["https://evil.example/cb"]})
    assert r.status_code == 400


EVIL = [
    "http://localhost.evil.com/cb",               # prefix trick
    "http://localhost@evil.com/cb",               # userinfo trick
    "http://127.0.0.1.evil.com/cb",
    "http://localhost:80@evil.com/",
    "https://claude.ai.evil.com/api/mcp/auth_callback",
    "https://evil.com/https://claude.ai/api/mcp/auth_callback",
    "https://claude.ai@evil.com/api/mcp/auth_callback",
    "https://claude.ai/api/mcp/auth_callback/../../steal",
    "https://claude.ai/api/mcp/auth_callbackX",   # path boundary
    "https://claude.ai/api/other",
    "https://claude.ai:8443/api/mcp/auth_callback",
    "http://claude.ai/api/mcp/auth_callback",      # downgrade to http
    "https://localhost/cb",                        # loopback must be plain http
    "javascript:alert(1)", "ftp://localhost/x", "//evil.com/cb", "http://",
    "https://claude.ai/api/mcp/auth_callback#frag",
    "https://claude.ai/api/mcp/auth_callback\\evil.com",
    "http://localhost/cb\nHost: evil.com",
]
GOOD = ["https://claude.ai/api/mcp/auth_callback",
        "https://claude.ai/api/mcp/auth_callback?x=1",
        "http://localhost:53682/callback", "http://127.0.0.1:8080/cb", "http://localhost/cb",
        "http://[::1]:9000/cb"]


@pytest.mark.parametrize("uri", EVIL)
async def test_open_redirect_variants_rejected(client, uri):
    r = await client.post("/oauth/register", json={"redirect_uris": [uri]})
    assert r.status_code == 400, f"{uri!r} must be rejected"
    r = await client.post("/oauth/register", json={"redirect_uris": [GOOD[0], uri]})
    assert r.status_code == 400                        # one bad URI poisons the registration


@pytest.mark.parametrize("uri", GOOD)
async def test_legitimate_redirects_accepted(client, uri):
    r = await client.post("/oauth/register", json={"redirect_uris": [uri]})
    assert r.status_code == 201, uri
