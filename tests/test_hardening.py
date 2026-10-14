import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy import exc as sa_exc
from starlette.requests import Request

from app import breaker, maintenance, ratelimit
from app.auth.passwords import hash_password
from app.config import get_settings
from app.connectors.sql import SqlConnector
from app.db.models import (AuditLog, Base, OAuthCode, RefreshToken, User)
from app.db.session import SessionLocal, engine
from app.main import app
from app.mcp_tools import data
from app.mcp_tools import exports as export_tools
from app.mcp_tools.server import current_user_id
from app.observability import JsonFormatter, request_id_var, safe_path
from app.sources import service


@pytest_asyncio.fixture
async def env(tmp_path):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    p = tmp_path / "h.db"
    db = sqlite3.connect(p)
    db.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    db.executemany("INSERT INTO t VALUES (?,?)", [(i, f"v{i}") for i in range(50)])
    db.commit(); db.close()
    async with SessionLocal() as s:
        u = User(email="h@x.in", name="H", password_hash=hash_password("pw12345678"))
        o = User(email="o@x.in", name="O", password_hash=hash_password("pw12345678"))
        s.add_all([u, o])
        await s.commit()
        a = await service.create_source(s, u.id, "a", "sqlite", {"database": str(p)})
        b = await service.create_source(s, o.id, "b", "sqlite", {"database": str(p)})
    current_user_id.set(u.id)
    yield {"user": u.id, "other": o.id, "src": a.id, "other_src": b.id}


# ------------------------------------------------------------------ rate limiting
def test_sliding_window_and_retry_after(monkeypatch):
    t = [1000.0]
    monkeypatch.setattr(ratelimit, "_now", lambda: t[0])
    lim = ratelimit.SlidingWindow()
    assert [lim.hit("k", 3, 60) for _ in range(3)] == [None, None, None]
    retry = lim.hit("k", 3, 60)
    assert retry == pytest.approx(60, abs=0.5)
    assert lim.hit("other", 3, 60) is None                  # keys are independent
    t[0] += 30
    assert lim.hit("k", 3, 60) is not None                  # window not yet free
    t[0] += 31
    assert lim.hit("k", 3, 60) is None                      # window slid


async def test_query_rate_limit_is_per_user_and_audited(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_queries_per_min", 3)
    for _ in range(3):
        await data.run_query(env["src"], "SELECT 1")
    with pytest.raises(ValueError, match="Rate limit exceeded for queries"):
        await data.run_query(env["src"], "SELECT 1")
    current_user_id.set(env["other"])                       # someone else is unaffected
    assert (await data.run_query(env["other_src"], "SELECT 1"))["row_count"] == 1
    async with SessionLocal() as s:
        logs = (await s.execute(select(AuditLog).where(AuditLog.status == "rejected"))).scalars().all()
    assert any("Rate limit" in (l.error or "") for l in logs)


async def test_overall_tool_limit(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_tools_per_min", 2)
    await data.get_schema_overview(env["src"])
    await data.search_schema(env["src"], "t")
    with pytest.raises(ValueError, match="Rate limit exceeded for tools"):
        await data.get_schema_overview(env["src"])


async def test_export_rate_limit(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_exports_per_hour", 1)
    await export_tools.export_result(env["src"], "SELECT id FROM t")
    with pytest.raises(ValueError, match="Rate limit exceeded for exports"):
        await export_tools.export_result(env["src"], "SELECT id FROM t")


def make_client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_login_is_rate_limited_per_ip(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_login_per_min_ip", 3)
    async with make_client() as c:
        codes = [(await c.post("/login", data={"email": "nobody@x.in", "password": "x"})).status_code
                 for _ in range(5)]
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
        r = await c.post("/login", data={"email": "h@x.in", "password": "pw12345678"})
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1   # even valid creds


async def test_token_and_register_endpoints_rate_limited(env, monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_token_per_min_ip", 2)
    async with make_client() as c:
        for _ in range(2):
            await c.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": "x",
                                               "refresh_token": "y"})
        r = await c.post("/oauth/token", data={"grant_type": "refresh_token", "client_id": "x",
                                               "refresh_token": "y"})
        assert r.status_code == 429


def _req(headers, peer="10.0.0.9"):
    return Request({"type": "http", "headers": [(k.encode(), v.encode()) for k, v in headers],
                    "client": (peer, 1234), "method": "GET", "path": "/"})


def test_client_ip_ignores_spoofed_forwarded_for_unless_trusted(monkeypatch):
    spoof = [("x-forwarded-for", "6.6.6.6, 1.2.3.4")]
    assert ratelimit.client_ip(_req(spoof)) == "10.0.0.9"                  # not trusted: ignored
    monkeypatch.setattr(get_settings(), "trusted_proxy_count", 1)
    assert ratelimit.client_ip(_req(spoof)) == "1.2.3.4"                   # the proxy-added hop
    assert ratelimit.client_ip(_req([])) == "10.0.0.9"                     # header missing


# ------------------------------------------------------------------ circuit breaker
def _conn_error():
    return sa_exc.OperationalError("SELECT 1", {}, Exception("connection refused"))


async def test_breaker_opens_on_connection_failures_then_recovers(env, monkeypatch):
    calls = {"n": 0}

    async def boom(self, sql, max_rows, timeout_s):
        calls["n"] += 1
        raise _conn_error()

    monkeypatch.setattr(SqlConnector, "execute", boom)
    t = [5000.0]
    monkeypatch.setattr(breaker, "_now", lambda: t[0])
    for _ in range(5):
        with pytest.raises(ValueError, match="Database error"):
            await data.run_query(env["src"], "SELECT 1")
    assert calls["n"] == 5
    with pytest.raises(ValueError, match="temporarily unavailable"):
        await data.run_query(env["src"], "SELECT 1")
    assert calls["n"] == 5                                   # the database was NOT contacted
    current_user_id.set(env["other"])                        # other sources unaffected
    with pytest.raises(ValueError, match="Database error"):
        await data.run_query(env["other_src"], "SELECT 1")
    current_user_id.set(env["user"])
    t[0] += get_settings().breaker_open_s + 1                # window passes -> retried
    with pytest.raises(ValueError, match="Database error"):
        await data.run_query(env["src"], "SELECT 1")
    assert calls["n"] == 7


async def test_breaker_ignores_user_errors_timeouts_and_resets_on_success(env, monkeypatch):
    for _ in range(12):                                      # bad SQL is the user's problem
        with pytest.raises(ValueError):
            await data.run_query(env["src"], "SELECT nope FROM t")
    assert (await data.run_query(env["src"], "SELECT 1"))["row_count"] == 1
    assert not breaker.is_connection_failure(TimeoutError("x"))
    assert not breaker.is_connection_failure(sa_exc.OperationalError(
        "q", {}, Exception("canceling statement due to statement timeout")))
    assert breaker.is_connection_failure(_conn_error())
    assert breaker.is_connection_failure(ConnectionRefusedError())
    # 4 failures, one success, 4 more failures: never reaches 5 consecutive
    seq = iter([True] * 4 + [False] + [True] * 4)

    async def flaky(self, sql, max_rows, timeout_s):
        if next(seq):
            raise _conn_error()
        return {"columns": [], "rows": [], "row_count": 0, "truncated": False, "elapsed_ms": 1}

    monkeypatch.setattr(SqlConnector, "execute", flaky)
    for _ in range(9):
        try:
            await data.run_query(env["src"], "SELECT 1")
        except ValueError as e:
            assert "temporarily unavailable" not in str(e)


# ------------------------------------------------------------------ metrics / health / headers
async def test_metrics_count_tool_calls_and_require_token(env, monkeypatch):
    await data.run_query(env["src"], "SELECT 1")
    with pytest.raises(ValueError):
        await data.run_query(env["src"], "DELETE FROM t")
    async with make_client() as c:
        assert (await c.get("/metrics")).status_code == 404            # disabled by default
        monkeypatch.setattr(get_settings(), "metrics_token", "m-secret")
        assert (await c.get("/metrics")).status_code == 401
        assert (await c.get("/metrics", headers={"Authorization": "Bearer wrong"})).status_code == 401
        r = await c.get("/metrics", headers={"Authorization": "Bearer m-secret"})
        assert r.status_code == 200
        assert 'connector_tool_calls_total{status="ok",tool="run_query"}' in r.text
        assert 'connector_tool_calls_total{status="rejected",tool="run_query"}' in r.text
        assert "connector_tool_seconds_bucket" in r.text and "connector_http_requests_total" in r.text


async def test_health_and_readiness(env):
    async with make_client() as c:
        assert (await c.get("/healthz")).json() == {"status": "ok"}
        assert (await c.get("/readyz")).json() == {"status": "ready"}


async def test_security_headers_request_id_and_host_validation(env, monkeypatch):
    async with make_client() as c:
        r = await c.get("/healthz", headers={"X-Request-ID": "trace-abc.123"})
        assert r.headers["x-request-id"] == "trace-abc.123"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert "strict-transport-security" not in r.headers            # plain http
        bad = await c.get("/healthz", headers={"X-Request-ID": "bad id!<script>"})
        assert bad.headers["x-request-id"] != "bad id!<script>" and len(bad.headers["x-request-id"]) == 16
        monkeypatch.setattr(get_settings(), "public_base_url", "https://test")
        assert "max-age" in (await c.get("/healthz")).headers["strict-transport-security"]
        monkeypatch.setattr(get_settings(), "public_base_url", "http://test")
        evil = await c.get("/healthz", headers={"Host": "evil.example"})
        assert evil.status_code == 400                                   # Host header attack


async def test_logs_are_json_and_never_contain_tokens_or_sql(env, caplog):
    caplog.set_level(logging.INFO, logger="connector")
    async with make_client() as c:
        await c.get("/files/SECRET.TOKEN.VALUE")
        await c.get("/oauth/authorize?client_id=x&redirect_uri=y&code_challenge=SECRETCHALLENGE")
    await data.run_query(env["src"], "SELECT 'sensitive-literal' AS x")
    blob = " ".join(json.dumps(r.__dict__, default=str) for r in caplog.records)
    assert "SECRET.TOKEN.VALUE" not in blob and "SECRETCHALLENGE" not in blob
    assert "sensitive-literal" not in blob                              # SQL stays in the audit table
    assert "/files/[redacted]" in blob
    rec = next(r for r in caplog.records if getattr(r, "event", "") == "tool_call")
    request_id_var.set("rid-1")
    out = json.loads(JsonFormatter().format(rec))
    assert out["event"] == "tool_call" and out["tool"] == "run_query" and out["request_id"] == "rid-1"
    assert safe_path("/files/abc") == "/files/[redacted]" and safe_path("/login") == "/login"


async def test_server_refuses_to_start_with_weak_or_missing_secrets(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "jwt_secret", "short")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        async with app.router.lifespan_context(app):
            pass
    monkeypatch.undo()
    monkeypatch.setattr(get_settings(), "master_key", "")
    with pytest.raises(RuntimeError, match="MASTER_KEY"):
        async with app.router.lifespan_context(app):
            pass


# ------------------------------------------------------------------ maintenance
async def test_maintenance_removes_only_what_it_should(env, monkeypatch):
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(get_settings(), "audit_retention_days", 30)
    async with SessionLocal() as s:
        s.add_all([
            OAuthCode(code_hash="used", client_id="c", user_id=env["user"], redirect_uri="r",
                      code_challenge="x", expires_at=now + timedelta(minutes=5), used=True),
            OAuthCode(code_hash="old", client_id="c", user_id=env["user"], redirect_uri="r",
                      code_challenge="x", expires_at=now - timedelta(days=3)),
            OAuthCode(code_hash="live", client_id="c", user_id=env["user"], redirect_uri="r",
                      code_challenge="x", expires_at=now + timedelta(minutes=5)),
            RefreshToken(token_hash="expired", client_id="c", user_id=env["user"],
                         expires_at=now - timedelta(days=1)),
            RefreshToken(token_hash="revoked-live", client_id="c", user_id=env["user"],
                         expires_at=now + timedelta(days=5), revoked=True),
            RefreshToken(token_hash="active", client_id="c", user_id=env["user"],
                         expires_at=now + timedelta(days=5)),
            AuditLog(tool="old", status="ok", ts=now - timedelta(days=45)),
            AuditLog(tool="recent", status="ok", ts=now - timedelta(days=2)),
        ])
        await s.commit()
    done = await maintenance.run_once()
    assert done["oauth_codes"] == 2 and done["refresh_tokens"] == 1 and done["audit_rows"] == 1
    async with SessionLocal() as s:
        assert {c.code_hash for c in (await s.execute(select(OAuthCode))).scalars()} == {"live"}
        # revoked-but-unexpired tokens are kept: they are how token replay is detected
        assert {t.token_hash for t in (await s.execute(select(RefreshToken))).scalars()} == {
            "revoked-live", "active"}
        assert {a.tool for a in (await s.execute(select(AuditLog))).scalars()} >= {"recent"}
        assert "old" not in {a.tool for a in (await s.execute(select(AuditLog))).scalars()}
