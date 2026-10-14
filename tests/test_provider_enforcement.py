"""Per-source provider allow-list: EVERY tool that touches a data source (or an export of one) must
refuse a provider the owner has not enabled, with no side effects, and audit the refusal."""
import re
import sqlite3
from datetime import date, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.auth.passwords import hash_password
from app.context import current_provider
from app.db.models import AuditLog, Base, DataSource, Export, SemanticItem, User
from app.db.session import SessionLocal, engine
from app.main import app
from app.mcp_tools import analysis, data, exports, scripts, semantic
from app.mcp_tools.server import current_user_id, list_data_sources, mcp
from app.providers import LABELS, PROVIDERS
from app.sources import service

PW = "pw12345678!"
DENIED = "not enabled for"


@pytest_asyncio.fixture
async def env(tmp_path):
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    path = tmp_path / "e.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, d TEXT, amount NUMERIC)")
    rows = [(i, (date(2026, 1, 1) + timedelta(days=i)).isoformat(), 10 + i % 7) for i in range(80)]
    db.executemany("INSERT INTO t VALUES (?,?,?)", rows)
    db.commit(); db.close()
    async with SessionLocal() as s:
        u = User(email="e@x.in", name="E", password_hash=hash_password(PW), must_change_password=False)
        o = User(email="o@x.in", name="O", password_hash=hash_password(PW), must_change_password=False)
        s.add_all([u, o])
        await s.commit()
        src = await service.create_source(s, u.id, "main", "sqlite", {"database": str(path)})
    current_user_id.set(u.id)
    current_provider.set("claude")
    m = await exports.export_result(src.id, "SELECT id FROM t")          # made while Claude is allowed
    yield {"src": src.id, "eid": m["export_id"], "user": u.id, "other": o.id, "path": path}


async def set_allowed(source_id, allowed):
    async with SessionLocal() as s:
        (await s.get(DataSource, source_id)).allowed_providers = allowed
        await s.commit()


# every tool that takes a source_id or export_id, called validly
CALLS = {
    "get_schema_overview": lambda s, e: data.get_schema_overview(s),
    "search_schema": lambda s, e: data.search_schema(s, "t"),
    "describe_table": lambda s, e: data.describe_table(s, "t"),
    "run_query": lambda s, e: data.run_query(s, "SELECT 1 AS a"),
    "refresh_schema_cache": lambda s, e: data.refresh_schema_cache(s),
    "profile_table": lambda s, e: analysis.profile_table(s, "t"),
    "profile_column": lambda s, e: analysis.profile_column(s, "t", "id"),
    "validate_result": lambda s, e: analysis.validate_result(s, "SELECT id FROM t"),
    "get_relationships": lambda s, e: analysis.get_relationships(s, "t"),
    "compare_periods": lambda s, e: analysis.compare_periods(
        s, "t", "d", "amount", "2026-01-01", "2026-02-01", "2026-02-01", "2026-03-01"),
    "detect_anomalies": lambda s, e: analysis.detect_anomalies(s, "t", "d", "amount"),
    "get_business_context": lambda s, e: semantic.get_business_context(s),
    "save_business_context": lambda s, e: semantic.save_business_context(s, "glossary", "x", "y"),
    "delete_business_context": lambda s, e: semantic.delete_business_context(s, "glossary", "x"),
    "export_result": lambda s, e: exports.export_result(s, "SELECT id FROM t"),
    "get_export_link": lambda s, e: exports.get_export_link(e),
    "generate_analysis_script": lambda s, e: scripts.generate_analysis_script(e, "generic"),
}


def test_the_matrix_covers_every_tool_that_takes_a_source_or_export_id():
    """Guard: a NEW tool that touches a source/export but is missing here fails this test, so the
    allow-list cannot be bypassed by forgetting to test (or enforce) it."""
    scoped = {t.name for t in mcp._tool_manager.list_tools()
              if {"source_id", "export_id"} & set(t.parameters.get("properties", {}))}
    assert scoped == set(CALLS), (f"missing from matrix: {scoped - set(CALLS)}; "
                                  f"stale in matrix: {set(CALLS) - scoped}")


# ------------------------------------------------------------------ denial
@pytest.mark.parametrize("tool", sorted(CALLS))
async def test_provider_not_on_allow_list_is_refused(env, tool):
    await set_allowed(env["src"], ["claude"])
    current_provider.set("openai")
    with pytest.raises(ValueError, match=DENIED) as e:
        await CALLS[tool](env["src"], env["eid"])
    assert LABELS["openai"] in str(e.value)
    async with SessionLocal() as s:
        denied = (await s.execute(select(AuditLog).where(AuditLog.status == "denied"))).scalars().all()
    assert denied and denied[-1].provider == "openai" and denied[-1].source_id == env["src"]
    assert denied[-1].user_id == env["user"] and denied[-1].tool == "provider_check"


@pytest.mark.parametrize("provider", PROVIDERS)
async def test_only_the_enabled_provider_gets_in(env, provider):
    """Not hard-coded to Claude: enabling a single provider lets exactly that one in."""
    await set_allowed(env["src"], [provider])
    for caller in PROVIDERS:
        current_provider.set(caller)
        if caller == provider:
            assert (await data.run_query(env["src"], "SELECT 1 AS a"))["rows"] == [[1]]
        else:
            with pytest.raises(ValueError, match=DENIED):
                await data.run_query(env["src"], "SELECT 1 AS a")


async def test_empty_allow_list_means_nobody_not_everybody(env):
    await set_allowed(env["src"], [])
    for caller in PROVIDERS:
        current_provider.set(caller)
        with pytest.raises(ValueError, match=DENIED):
            await data.run_query(env["src"], "SELECT 1")
        assert (await list_data_sources())["data_sources"] == []


async def test_denied_write_tools_leave_no_side_effects(env):
    await set_allowed(env["src"], ["claude"])
    current_provider.set("gemini")
    before = (await _export_count(), await _semantic_count(), await _cached_at(env["src"]))
    for tool in ("save_business_context", "delete_business_context", "export_result",
                 "refresh_schema_cache"):
        with pytest.raises(ValueError, match=DENIED):
            await CALLS[tool](env["src"], env["eid"])
    assert (await _export_count(), await _semantic_count(), await _cached_at(env["src"])) == before


async def _export_count():
    async with SessionLocal() as s:
        return len((await s.execute(select(Export))).scalars().all())


async def _semantic_count():
    async with SessionLocal() as s:
        return len((await s.execute(select(SemanticItem))).scalars().all())


async def _cached_at(source_id):
    async with SessionLocal() as s:
        return (await s.get(DataSource, source_id)).schema_cached_at


# ------------------------------------------------------------------ opt-in works for every tool
@pytest.mark.parametrize("tool", sorted(CALLS))
async def test_every_tool_works_once_the_owner_opts_in(env, tool):
    await set_allowed(env["src"], ["claude", "openai"])
    current_provider.set("openai")
    result = await CALLS[tool](env["src"], env["eid"])
    assert result                                    # ran to completion, no refusal


# ------------------------------------------------------------------ listing
async def test_list_data_sources_filters_and_reports_hidden_count(env, tmp_path):
    db2 = tmp_path / "second.db"
    c = sqlite3.connect(db2); c.execute("CREATE TABLE z(a)"); c.commit(); c.close()
    async with SessionLocal() as s:
        second = await service.create_source(s, env["user"], "second", "sqlite", {"database": str(db2)})
    await set_allowed(second.id, ["claude", "openai"])
    await set_allowed(env["src"], ["claude"])

    current_provider.set("claude")
    out = await list_data_sources()
    assert {x["name"] for x in out["data_sources"]} == {"main", "second"} and "note" not in out
    current_provider.set("openai")
    out = await list_data_sources()
    assert [x["name"] for x in out["data_sources"]] == ["second"]
    assert out["not_enabled_for_this_app"] == 1 and "ChatGPT / OpenAI" in out["note"]
    assert "http://test/sources" in out["note"]
    current_provider.set("gemini")
    out = await list_data_sources()
    assert out["data_sources"] == [] and out["not_enabled_for_this_app"] == 2


async def test_list_exports_only_shows_exports_of_enabled_sources(env):
    await set_allowed(env["src"], ["claude"])
    current_provider.set("claude")
    assert len((await exports.list_exports())["exports"]) == 1
    current_provider.set("openai")
    assert (await exports.list_exports())["exports"] == []
    await set_allowed(env["src"], ["claude", "openai"])
    assert len((await exports.list_exports())["exports"]) == 1


async def test_non_owner_still_sees_not_found_not_a_provider_message(env):
    """Provider checks must not turn into an existence oracle for other people's sources."""
    current_user_id.set(env["other"])
    current_provider.set("openai")
    with pytest.raises(ValueError, match="not found") as e:
        await data.run_query(env["src"], "SELECT 1")
    assert DENIED not in str(e.value)
    with pytest.raises(ValueError, match="not found|expired"):
        await exports.get_export_link(env["eid"])


async def test_new_sources_default_to_claude_only(env, tmp_path):
    async with SessionLocal() as s:
        sqlite_src = await s.get(DataSource, env["src"])
        assert sqlite_src.allowed_providers == ["claude"]

        class Up:
            def __init__(self, b):
                import io
                self._b = io.BytesIO(b)

            async def read(self, n=-1):
                return self._b.read(n)

        files = await service.create_file_source(s, env["user"], "files", [("a.csv", Up(b"a\n1\n"))])
        assert files.allowed_providers == ["claude"]


# ------------------------------------------------------------------ the web UI that edits it
def csrf_of(page):
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


async def login(email):
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    assert (await c.post("/login", data={"email": email, "password": PW})).status_code == 303
    return c


async def test_ui_shows_and_saves_the_allow_list_with_an_audit_trail(env):
    c = await login("e@x.in")
    try:
        page = (await c.get("/sources")).text
        assert 'name="providers" value="claude"' in page
        assert re.search(r'value="claude"\s+style="width:auto"\s+checked', page)
        assert not re.search(r'value="openai"\s+style="width:auto"\s+checked', page)
        csrf = csrf_of(page)
        r = await c.post(f"/sources/{env['src']}/providers",
                         data={"providers": ["claude", "openai", "evil", "claude"], "csrf": csrf})
        assert r.status_code == 200 and "ChatGPT / OpenAI" in r.text
        assert "sent to ChatGPT / OpenAI" in r.text              # the privacy consequence is spelled out
        async with SessionLocal() as s:
            assert (await s.get(DataSource, env["src"])).allowed_providers == ["claude", "openai"]
            log = (await s.execute(select(AuditLog).where(AuditLog.tool == "ui:set_providers"))).scalars().all()
        assert len(log) == 1 and "['claude'] -> ['claude', 'openai']" in log[0].sql_text
        # nothing ticked = nobody may use it
        r = await c.post(f"/sources/{env['src']}/providers", data={"csrf": csrf})
        assert "no app" in r.text
        async with SessionLocal() as s:
            assert (await s.get(DataSource, env["src"])).allowed_providers == []
    finally:
        await c.aclose()


async def test_ui_allow_list_edit_is_owner_only_and_csrf_protected(env):
    ce, co = await login("e@x.in"), await login("o@x.in")
    try:
        ocsrf = csrf_of((await co.get("/sources")).text)
        r = await co.post(f"/sources/{env['src']}/providers", data={"providers": ["openai"], "csrf": ocsrf})
        assert r.status_code == 404                              # someone else's source
        ecsrf = csrf_of((await ce.get("/sources")).text)
        r = await ce.post(f"/sources/{env['src']}/providers", data={"providers": ["openai"], "csrf": "forged"})
        assert r.status_code == 403
        async with SessionLocal() as s:
            assert (await s.get(DataSource, env["src"])).allowed_providers == ["claude"]   # unchanged
        assert ecsrf
    finally:
        await ce.aclose()
        await co.aclose()


async def test_audit_page_shows_the_app_column_and_denied_filter(env):
    await set_allowed(env["src"], ["claude"])
    current_provider.set("gemini")
    with pytest.raises(ValueError):
        await data.run_query(env["src"], "SELECT 1")
    async with SessionLocal() as s:
        s.add(User(email="adm@x.in", name="Adm", role="admin", password_hash=hash_password(PW),
                   must_change_password=False))
        await s.commit()
    c = await login("adm@x.in")
    try:
        page = (await c.get("/admin/audit?status=denied")).text
        assert "<th>App</th>" in page and "gemini" in page and "provider=gemini" in page
        assert "denied" in page and "<option selected>denied</option>" in page
    finally:
        await c.aclose()
