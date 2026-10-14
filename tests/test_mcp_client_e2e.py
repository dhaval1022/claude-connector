"""End to end over real HTTP: a real server process and the OFFICIAL MCP Python client, using a
personal API token the way OpenAI's Responses API / Gemini CLI would (a static bearer token).

This is the closest automated stand-in for "does a non-Claude MCP client work": it exercises the
full stack (auth middleware, provider identity, allow-list, lean schemas, tool annotations,
streamable-HTTP framing). It is NOT a test against ChatGPT or Gemini themselves."""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ROOT = Path(__file__).resolve().parent.parent
ROWS = 37

SEED = r'''
import asyncio, json, sqlite3, sys
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.auth import api_tokens
from app.auth.passwords import hash_password
from app.db.models import ApiToken, DataSource, User
from app.db.session import SessionLocal
from app.sources import service

db_file = sys.argv[1]

async def main():
    async with SessionLocal() as s:
        u = User(email="e2e@x.in", name="E", password_hash=hash_password("pw12345678!"),
                 must_change_password=False)
        s.add(u); await s.commit()
        a = await service.create_source(s, u.id, "open_src", "sqlite", {"database": db_file})
        b = await service.create_source(s, u.id, "claude_only", "sqlite", {"database": db_file})
        a.allowed_providers = ["claude", "openai"]
        await s.commit()
        out = {"open": a.id, "closed": b.id}
        for name, prov in (("openai", "openai"), ("claude", "claude"), ("gemini", "gemini")):
            out[name], _ = await api_tokens.create_token(s, u, name, prov, 30)
        out["revoked"], row = await api_tokens.create_token(s, u, "revoked", "openai", 30)
        row.revoked = True
        out["expired"], row2 = await api_tokens.create_token(s, u, "expired", "openai", 30)
        row2.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        await s.commit()
        print(json.dumps(out))

asyncio.run(main())
'''


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    data_db = tmp / "data.db"
    c = sqlite3.connect(data_db)
    c.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    c.executemany("INSERT INTO t VALUES (?,?)", [(i, f"v{i}") for i in range(ROWS)])
    c.commit()
    c.close()
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    env = {**os.environ, "CONNECTOR_DATABASE_URL": f"sqlite+aiosqlite:///{(tmp / 'meta.db').as_posix()}",
           "CONNECTOR_DATA_DIR": str(tmp / "files"), "CONNECTOR_ENABLE_SQLITE": "true",
           "CONNECTOR_PUBLIC_BASE_URL": f"http://127.0.0.1:{port}",
           # hermetic: run from a temp dir so a developer's ./.env is never read
           "PYTHONPATH": str(ROOT)}
    subprocess.run([sys.executable, "-m", "app.cli", "migrate"], cwd=tmp, env=env, check=True,
                   capture_output=True, timeout=120)
    seeded = subprocess.run([sys.executable, "-c", SEED, str(data_db)], cwd=tmp, env=env,
                            check=True, capture_output=True, text=True, timeout=120)
    ids = json.loads(seeded.stdout.strip().splitlines()[-1])
    log = open(tmp / "server.log", "w")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port),
                             "--no-access-log"], cwd=tmp, env=env, stdout=log,
                            stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                if httpx.get(base + "/readyz", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)
        else:
            pytest.fail("server did not start:\n" + (tmp / "server.log").read_text())
        yield {"url": base + "/mcp", "base": base, "ids": ids, "log": tmp / "server.log"}
    finally:
        proc.terminate()
        proc.wait(timeout=20)
        log.close()


async def session_for(server, token):
    """Open a real MCP session the way a client would. Returns an async context manager."""
    headers = {"Authorization": f"Bearer {token}"} if token else None
    return streamablehttp_client(server["url"], headers=headers)


def payload(result):
    """The tool's JSON result from the MCP content blocks."""
    assert result.content, "empty result"
    return json.loads(result.content[0].text)


async def run_with(server, token, body):
    async with streamablehttp_client(server["url"],
                                     headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            return await body(session)


async def test_a_real_mcp_client_lists_lean_tools_with_annotations_using_an_openai_token(server):
    async def body(s):
        return (await s.list_tools()).tools
    tools = await run_with(server, server["ids"]["openai"], body)
    by = {t.name: t for t in tools}
    assert len(tools) == 20 and "run_query" in by and "generate_analysis_script" in by
    for t in tools:                                                 # over the wire, not in-process
        blob = json.dumps(t.inputSchema)
        for forbidden in ('"anyOf"', '"default"', '"title"', '"additionalProperties"'):
            assert forbidden not in blob, f"{t.name}: {forbidden}"
        assert t.annotations is not None and t.annotations.openWorldHint is False
    assert by["run_query"].annotations.readOnlyHint is True
    assert by["export_result"].annotations.readOnlyHint is False
    assert by["delete_business_context"].annotations.destructiveHint is True


async def test_openai_token_sees_only_sources_enabled_for_openai(server):
    async def body(s):
        return payload(await s.call_tool("list_data_sources", {}))
    out = await run_with(server, server["ids"]["openai"], body)
    assert [x["name"] for x in out["data_sources"]] == ["open_src"]
    assert out["not_enabled_for_this_app"] == 1 and "ChatGPT / OpenAI" in out["note"]


async def test_claude_token_sees_everything_gemini_sees_nothing(server):
    async def body(s):
        return payload(await s.call_tool("list_data_sources", {}))
    both = await run_with(server, server["ids"]["claude"], body)
    assert {x["name"] for x in both["data_sources"]} == {"open_src", "claude_only"}
    none = await run_with(server, server["ids"]["gemini"], body)
    assert none["data_sources"] == [] and none["not_enabled_for_this_app"] == 2


async def test_queries_work_on_an_enabled_source_with_exact_results(server):
    async def body(s):
        q = payload(await s.call_tool("run_query", {
            "source_id": server["ids"]["open"], "sql": "SELECT COUNT(*) AS n FROM t"}))
        d = payload(await s.call_tool("describe_table", {
            "source_id": server["ids"]["open"], "table": "t", "sample_rows": 2}))
        return q, d
    q, d = await run_with(server, server["ids"]["openai"], body)
    assert q["rows"] == [[ROWS]] and q["truncated"] is False and q["warnings"] == []
    assert [c["name"] for c in d["columns"]] == ["id", "v"] and len(d["sample"]["rows"]) == 2


async def test_a_source_not_enabled_for_the_app_is_refused_over_the_wire(server):
    async def body(s):
        return await s.call_tool("run_query", {
            "source_id": server["ids"]["closed"], "sql": "SELECT COUNT(*) FROM t"})
    result = await run_with(server, server["ids"]["openai"], body)
    assert result.isError is True
    assert "not enabled for ChatGPT / OpenAI" in result.content[0].text
    assert "SELECT" not in result.content[0].text and str(ROWS) not in result.content[0].text


async def test_optional_arguments_may_be_omitted_or_null_over_the_wire(server):
    async def body(s):
        a = await s.call_tool("list_script_templates", {})
        b = await s.call_tool("generate_analysis_script", {
            "export_id": "does-not-exist", "template": "generic", "item_column": None,
            "params_json": None})
        return a, b
    a, b = await run_with(server, server["ids"]["openai"], body)
    assert a.isError is False and "abc_xyz" in a.content[0].text
    assert b.isError is True and "Export not found" in b.content[0].text   # validated, then refused


async def test_an_export_flows_through_the_real_client_and_download_link_works(server):
    async def body(s):
        return payload(await s.call_tool("export_result", {
            "source_id": server["ids"]["open"], "sql": "SELECT id, v FROM t ORDER BY id"}))
    m = await run_with(server, server["ids"]["openai"], body)
    assert m["rows"] == ROWS and m["download_url"].startswith(server["base"] + "/files/")
    r = httpx.get(m["download_url"])
    assert r.status_code == 200 and r.headers["x-export-sha256"] == m["sha256"]
    assert len(r.text.strip().splitlines()) == ROWS + 1


@pytest.mark.parametrize("which", ["none", "revoked", "expired", "garbage", "malformed"])
async def test_bad_credentials_are_refused_by_a_real_client(server, which):
    token = {"none": None, "revoked": server["ids"]["revoked"], "expired": server["ids"]["expired"],
             "garbage": "mk_" + "A" * 43, "malformed": "not-a-token"}[which]
    headers = {"Authorization": f"Bearer {token}"} if token else None
    with pytest.raises(BaseException) as e:
        async with streamablehttp_client(server["url"], headers=headers) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                await s.list_tools()
    assert "401" in str(e.value) or "Unauthorized" in str(e.value) or "Exception" in repr(e.value)


@pytest.mark.parametrize("suffix", ["", "/"])
async def test_mcp_url_works_with_and_without_trailing_slash_and_never_redirects(server, suffix):
    """Clients that do not follow redirects on POST must still work with a pasted https://host/mcp."""
    url = server["url"] + suffix
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    anon = httpx.post(url, json=ping, follow_redirects=False)
    assert anon.status_code == 401, f"{url}: got {anon.status_code}"        # not a 307
    assert "resource_metadata=" in anon.headers["www-authenticate"]
    ok = httpx.post(url, json=ping, follow_redirects=False, headers={
        "Authorization": f"Bearer {server['ids']['openai']}",
        "Accept": "application/json, text/event-stream"})
    assert ok.status_code == 200 and ok.json()["id"] == 1, f"{url}: {ok.status_code} {ok.text[:100]}"


async def test_unauthenticated_probe_returns_the_oauth_discovery_challenge(server):
    r = httpx.post(server["url"], json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]
    meta = httpx.get(server["base"] + "/.well-known/oauth-protected-resource/mcp").json()
    assert meta["resource"] == server["url"]


async def test_no_token_or_secret_ever_reached_the_server_log(server):
    text = server["log"].read_text(errors="replace")
    for secret in (server["ids"]["openai"], server["ids"]["claude"], server["ids"]["gemini"],
                   server["ids"]["revoked"]):
        assert secret not in text and secret[3:] not in text
    assert "/files/" not in text.replace("/files/[redacted]", "")
    assert '"provider": "openai"' in text            # the provider IS logged on every tool call
