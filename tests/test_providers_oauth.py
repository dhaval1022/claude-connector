"""Provider identity through OAuth (ChatGPT / Gemini CLI / Claude), discovery aliases, and the
/mcp auth middleware accepting OAuth JWTs and personal API tokens."""
import base64
import hashlib
import logging
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.auth import api_tokens
from app.auth.mcp_auth import McpAuthMiddleware
from app.auth.passwords import hash_password
from app.auth.tokens import verify_access_token
from app.config import get_settings
from app.context import current_provider, current_user_id
from app.db.models import ApiToken, Base, OAuthClient, OAuthCode, RefreshToken, User
from app.db.session import SessionLocal, engine
from app.main import app
from app.providers import clean_allowed, is_allowed, normalize, provider_for_redirect_uris

CLAUDE = "https://claude.ai/api/mcp/auth_callback"
CHATGPT_FIXED = "https://chatgpt.com/connector_platform_oauth_redirect"
CHATGPT_APP = "https://chatgpt.com/connector/oauth/abc123XYZ"
LOOPBACK = "http://localhost:53682/callback"
PW = "pw12345678!"


@pytest_asyncio.fixture
async def env():
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as s:
        u = User(email="p@x.in", name="P", password_hash=hash_password(PW))
        s.add(u)
        await s.commit()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://test") as c:
        yield {"c": c, "user": u.id}


# ------------------------------------------------------------------ pure provider logic
@pytest.mark.parametrize("uris,expected", [
    ([CLAUDE], "claude"), ([CHATGPT_FIXED], "openai"), ([CHATGPT_APP], "openai"),
    ([CHATGPT_FIXED, CHATGPT_APP], "openai"),
    ([LOOPBACK], ""), (["http://127.0.0.1:9/cb"], ""), (["http://[::1]:9/cb"], ""),
    ([CLAUDE, CHATGPT_FIXED], ""),                    # mixed -> ask the user
    (["https://unknown.example/cb"], ""), ([], ""),
])
def test_provider_for_redirect_uris(uris, expected):
    assert provider_for_redirect_uris(uris) == expected


def test_normalize_allowed_and_cleaning():
    assert normalize("OpenAI ") == "openai" and normalize("nonsense") == "claude"
    assert normalize(None) == "claude"                     # legacy tokens
    assert clean_allowed(["gemini", "claude", "evil", "claude", " OPENAI "]) == [
        "claude", "openai", "gemini"]
    assert clean_allowed([]) == [] and clean_allowed(None) == []
    assert is_allowed(["claude"], "claude") and not is_allowed(["claude"], "openai")
    assert not is_allowed(None, "claude") and not is_allowed([], "claude")


# ------------------------------------------------------------------ redirect allow-list
@pytest.mark.parametrize("uri", [CHATGPT_FIXED, CHATGPT_APP, CHATGPT_FIXED + "?x=1",
                                 "https://chatgpt.com/connector/oauth/a-b_c"])
async def test_chatgpt_callbacks_are_accepted(env, uri):
    r = await env["c"].post("/oauth/register", json={"redirect_uris": [uri]})
    assert r.status_code == 201, uri


@pytest.mark.parametrize("uri", [
    "https://chatgpt.com.evil.com/connector_platform_oauth_redirect",
    "https://evil.com/connector_platform_oauth_redirect",
    "https://chatgpt.com@evil.com/connector/oauth/x",
    "http://chatgpt.com/connector_platform_oauth_redirect",          # downgrade to http
    "https://chatgpt.com/connector_platform_oauth_redirectX",
    "https://chatgpt.com/connector/oauthX/abc",
    "https://chatgpt.com/connector/oauth/../../steal",
    "https://chatgpt.com/other",
    "https://chatgpt.com:8443/connector_platform_oauth_redirect",
    "https://notchatgpt.com/connector/oauth/a",
    "https://chatgpt.com/connector/oauth/a#frag",
    "https://chat.openai.com/connector_platform_oauth_redirect",     # not allowed unless configured
])
async def test_chatgpt_lookalike_callbacks_are_rejected(env, uri):
    r = await env["c"].post("/oauth/register", json={"redirect_uris": [uri]})
    assert r.status_code == 400, uri


async def test_rejection_is_logged_with_host_and_path_but_never_the_query(env, caplog):
    caplog.set_level(logging.INFO, logger="connector")
    r = await env["c"].post("/oauth/register", json={
        "redirect_uris": ["https://new-ai.example/oauth/cb?secret=TOPSECRET&code=abc"],
        "client_name": "New AI"})
    assert r.status_code == 400
    ev = next(x for x in caplog.records if getattr(x, "event", "") == "oauth_redirect_rejected")
    assert ev.rejected == ["https://new-ai.example/oauth/cb"] and ev.client_name == "New AI"
    assert "TOPSECRET" not in str(ev.__dict__)


async def test_client_provider_hint_is_stored(env):
    for uri, hint in [(CLAUDE, "claude"), (CHATGPT_APP, "openai"), (LOOPBACK, "")]:
        cid = (await env["c"].post("/oauth/register", json={"redirect_uris": [uri]})).json()["client_id"]
        async with SessionLocal() as s:
            assert (await s.get(OAuthClient, cid)).provider_hint == hint


# ------------------------------------------------------------------ discovery aliases
@pytest.mark.parametrize("path", ["/.well-known/oauth-authorization-server",
                                  "/.well-known/oauth-authorization-server/mcp",
                                  "/.well-known/openid-configuration"])
async def test_authorization_server_metadata_on_every_probe_path(env, path):
    r = await env["c"].get(path)
    assert r.status_code == 200
    j = r.json()
    assert j["issuer"] == "http://test" and j["token_endpoint"].endswith("/oauth/token")
    assert j["code_challenge_methods_supported"] == ["S256"]


@pytest.mark.parametrize("path", ["/.well-known/oauth-protected-resource",
                                  "/.well-known/oauth-protected-resource/mcp"])
async def test_protected_resource_metadata_on_every_probe_path(env, path):
    j = (await env["c"].get(path)).json()
    assert j["resource"] == "http://test/mcp" and j["authorization_servers"] == ["http://test"]


# ------------------------------------------------------------------ consent + provider claim
def pkce():
    verifier = "v" * 64
    chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, chal


async def register(c, redirect):
    return (await c.post("/oauth/register", json={"redirect_uris": [redirect],
                                                  "client_name": "t"})).json()["client_id"]


async def authorize(c, cid, redirect, chal, provider=None, password=PW):
    data = {"client_id": cid, "redirect_uri": redirect, "code_challenge": chal, "state": "s",
            "email": "p@x.in", "password": password}
    if provider is not None:
        data["provider"] = provider
    return await c.post("/oauth/authorize", data=data)


async def exchange(c, cid, redirect, location, verifier):
    code = parse_qs(urlparse(location).query)["code"][0]
    return await c.post("/oauth/token", data={
        "grant_type": "authorization_code", "client_id": cid, "code": code,
        "redirect_uri": redirect, "code_verifier": verifier})


async def test_consent_page_for_loopback_client_requires_choosing_an_app(env):
    cid = await register(env["c"], LOOPBACK)
    _, chal = pkce()
    page = (await env["c"].get("/oauth/authorize", params={
        "client_id": cid, "redirect_uri": LOOPBACK, "code_challenge": chal})).text
    assert "name=provider" in page and "required" in page and "Choose..." in page
    for label in ("Claude (Anthropic)", "ChatGPT / OpenAI", "Gemini (Google)", "Other"):
        assert label in page


async def test_consent_page_for_known_hosts_shows_detected_app_without_a_choice(env):
    _, chal = pkce()
    for uri, label in [(CHATGPT_FIXED, "ChatGPT / OpenAI"), (CLAUDE, "Claude (Anthropic)")]:
        cid = await register(env["c"], uri)
        page = (await env["c"].get("/oauth/authorize", params={
            "client_id": cid, "redirect_uri": uri, "code_challenge": chal})).text
        assert "Detected app" in page and label in page and "<select" not in page


async def test_loopback_signin_without_a_valid_choice_is_refused_and_creates_nothing(env):
    cid = await register(env["c"], LOOPBACK)
    _, chal = pkce()
    for provider in (None, "", "evil", "CLAUDE-ish"):
        r = await authorize(env["c"], cid, LOOPBACK, chal, provider)
        assert r.status_code == 200 and "Choose which app" in r.text and "location" not in r.headers
    async with SessionLocal() as s:
        assert (await s.execute(select(OAuthCode))).first() is None


@pytest.mark.parametrize("choice", ["claude", "openai", "gemini", "other"])
async def test_provider_choice_flows_into_code_access_token_and_refresh(env, choice):
    cid = await register(env["c"], LOOPBACK)
    verifier, chal = pkce()
    r = await authorize(env["c"], cid, LOOPBACK, chal, choice)
    assert r.status_code == 303
    async with SessionLocal() as s:
        assert (await s.execute(select(OAuthCode))).scalar_one().provider == choice
    t = await exchange(env["c"], cid, LOOPBACK, r.headers["location"], verifier)
    assert t.status_code == 200
    claims = verify_access_token(t.json()["access_token"])
    assert claims["prv"] == choice and claims["sub"] == env["user"]
    r2 = await env["c"].post("/oauth/token", data={
        "grant_type": "refresh_token", "client_id": cid, "refresh_token": t.json()["refresh_token"]})
    assert r2.status_code == 200
    assert verify_access_token(r2.json()["access_token"])["prv"] == choice     # inherited
    async with SessionLocal() as s:
        assert {x.provider for x in (await s.execute(select(RefreshToken))).scalars()} == {choice}


@pytest.mark.parametrize("uri,posted,expected", [
    (CLAUDE, "openai", "claude"),            # a posted value cannot override a known host
    (CHATGPT_FIXED, "claude", "openai"),
    (CHATGPT_APP, "gemini", "openai"),
    (CHATGPT_APP, "", "openai"),             # and none is needed
])
async def test_known_hosts_cannot_be_relabelled_by_the_form(env, uri, posted, expected):
    cid = await register(env["c"], uri)
    _, chal = pkce()
    r = await authorize(env["c"], cid, uri, chal, posted)
    assert r.status_code == 303
    async with SessionLocal() as s:
        assert (await s.execute(select(OAuthCode))).scalar_one().provider == expected


async def test_failed_login_keeps_the_chosen_app_selected(env):
    cid = await register(env["c"], LOOPBACK)
    _, chal = pkce()
    r = await authorize(env["c"], cid, LOOPBACK, chal, "gemini", password="wrong")
    assert r.status_code == 200 and "Invalid email or password" in r.text
    assert 'value="gemini" selected' in r.text


# ------------------------------------------------------------------ /mcp auth middleware
class Probe:
    """Inner ASGI app that records the identity the middleware bound."""
    def __init__(self):
        self.seen = None

    async def __call__(self, scope, receive, send):
        self.seen = {"user": current_user_id.get(), "provider": current_provider.get()}
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def call(authorization: str | None, ip="9.9.9.9"):
    probe = Probe()
    sent = []

    async def send(m):
        sent.append(m)

    async def receive():
        return {"type": "http.request", "body": b""}

    headers = [(b"authorization", authorization.encode())] if authorization is not None else []
    scope = {"type": "http", "headers": headers, "client": (ip, 1), "method": "POST", "path": "/"}
    await McpAuthMiddleware(probe)(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], dict(start["headers"]), probe.seen


def jwt_for(user_id, **extra):
    s = get_settings()
    now = int(time.time())
    claims = {"sub": user_id, "cid": "c", "iat": now, "exp": now + 600,
              "aud": s.public_base_url.rstrip("/") + "/mcp", **extra}
    return jwt.encode(claims, s.jwt_secret, algorithm="HS256")


async def make_pat(env, provider="openai", days=30):
    async with SessionLocal() as s:
        owner = await s.get(User, env["user"])
        return await api_tokens.create_token(s, owner, "t", provider, days)


async def test_middleware_oauth_token_carries_its_provider(env):
    status, _, seen = await call("Bearer " + jwt_for(env["user"], prv="gemini"))
    assert status == 200 and seen == {"user": env["user"], "provider": "gemini"}


async def test_middleware_legacy_token_without_provider_claim_is_claude(env):
    status, _, seen = await call("Bearer " + jwt_for(env["user"]))
    assert status == 200 and seen["provider"] == "claude"


async def test_middleware_accepts_personal_api_token_with_its_provider(env):
    plain, _ = await make_pat(env, "openai")
    status, _, seen = await call("Bearer " + plain)
    assert status == 200 and seen == {"user": env["user"], "provider": "openai"}
    status, _, seen = await call("bearer   " + plain + "  ")        # case/whitespace tolerant
    assert status == 200


async def test_middleware_rejects_bad_expired_revoked_and_disabled(env):
    plain, row = await make_pat(env)
    cases = {
        "no header": None, "wrong scheme": "Basic abc", "garbage": "Bearer nonsense",
        "short mk_": "Bearer mk_short", "unknown mk_": "Bearer mk_" + "A" * 43,
        "tampered": "Bearer " + plain[:-2] + ("AA" if not plain.endswith("AA") else "BB"),
        "jwt wrong audience": "Bearer " + jwt.encode(
            {"sub": env["user"], "aud": "http://other/mcp", "exp": int(time.time()) + 60},
            get_settings().jwt_secret, algorithm="HS256"),
        "jwt expired": "Bearer " + jwt.encode(
            {"sub": env["user"], "aud": "http://test/mcp", "exp": int(time.time()) - 5},
            get_settings().jwt_secret, algorithm="HS256"),
    }
    for name, header in cases.items():
        status, headers, seen = await call(header)
        assert status == 401 and seen is None, name
        assert b"resource_metadata" in headers[b"www-authenticate"], name

    async with SessionLocal() as s:                                  # expired token
        r = await s.get(ApiToken, row.id)
        r.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await s.commit()
    assert (await call("Bearer " + plain))[0] == 401
    async with SessionLocal() as s:                                  # un-expire, then revoke
        r = await s.get(ApiToken, row.id)
        r.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        await s.commit()
    assert (await call("Bearer " + plain))[0] == 200
    async with SessionLocal() as s:
        assert await api_tokens.revoke_token(s, env["user"], row.id)
    assert (await call("Bearer " + plain))[0] == 401


async def test_middleware_disabled_user_loses_both_token_kinds_immediately(env):
    plain, _ = await make_pat(env)
    jwt_token = jwt_for(env["user"], prv="claude")
    assert (await call("Bearer " + plain))[0] == 200 and (await call("Bearer " + jwt_token))[0] == 200
    async with SessionLocal() as s:
        (await s.get(User, env["user"])).is_active = False
        await s.commit()
    assert (await call("Bearer " + plain))[0] == 401
    assert (await call("Bearer " + jwt_token))[0] == 401


async def test_middleware_throttles_credential_guessing_per_address_not_valid_users(env):
    plain, _ = await make_pat(env)
    for _ in range(60):
        assert (await call("Bearer mk_" + "Z" * 43, ip="6.6.6.6"))[0] == 401
    status, headers, _ = await call("Bearer mk_" + "Z" * 43, ip="6.6.6.6")
    assert status == 429 and headers[b"retry-after"] == b"60"
    assert (await call("Bearer mk_" + "Z" * 43, ip="7.7.7.7"))[0] == 401   # another address
    assert (await call("Bearer " + plain, ip="6.6.6.6"))[0] == 200         # a valid token still works
    for _ in range(100):                                                   # no header = not counted
        assert (await call(None, ip="8.8.8.8"))[0] == 401


async def test_identity_does_not_leak_out_of_the_request(env):
    plain, _ = await make_pat(env, "gemini")
    await call("Bearer " + plain)
    assert current_provider.get() == "claude"           # back to the default
    with pytest.raises(LookupError):
        current_user_id.get()
