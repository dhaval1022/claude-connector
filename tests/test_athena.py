"""Contract tests for the Athena connector against a FAKE boto3 client (no AWS account used).

These prove our handling of the Athena/Glue API shapes (header row, pagination, NULLs,
timeouts, state changes, credentials) - not that real Athena accepts the calls. Run a smoke test
against a real account before relying on it."""
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.auth.passwords import hash_password
from app.connectors.athena import AthenaConnector
from app.db.models import AuditLog, Base, DataSource, User
from app.db.session import SessionLocal, engine
from app.mcp_tools import data
from app.mcp_tools.server import current_user_id
from app.sources import service
from app.sources.crypto import decrypt_config

CFG = {"region": "ap-south-1", "s3_output": "s3://my-bucket/athena/", "database": "sales",
       "workgroup": "primary", "access_key_id": "AKIAEXAMPLE",
       "secret_access_key": "super-secret-key"}


class FakeAthena:
    def __init__(self):
        self.started, self.stopped = [], []
        self.state_script = ["RUNNING", "SUCCEEDED"]
        self.columns = [("id", "integer"), ("amount", "decimal"), ("name", "varchar"),
                        ("ratio", "double")]
        self.rows = [["1", "10.10", "a", "0.5"], ["2", "20.20", None, "1.5"],
                     ["3", "30.30", "", "2.5"]]
        self.scanned = 2_000_000_000
        self.fail_reason = None

    def start_query_execution(self, **kw):
        self.started.append(kw)
        return {"QueryExecutionId": f"q{len(self.started)}"}

    def get_query_execution(self, QueryExecutionId):
        state = self.state_script.pop(0) if len(self.state_script) > 1 else self.state_script[0]
        st = {"State": state}
        if state == "FAILED":
            st["StateChangeReason"] = self.fail_reason or "SYNTAX_ERROR: boom"
        return {"QueryExecution": {"Status": st,
                                   "Statistics": {"DataScannedInBytes": self.scanned}}}

    def stop_query_execution(self, QueryExecutionId):
        self.stopped.append(QueryExecutionId)

    def get_query_results(self, QueryExecutionId, MaxResults=1000, NextToken=None):
        meta = {"ColumnInfo": [{"Name": n, "Type": t} for n, t in self.columns]}
        def row(vals):
            return {"Data": [({"VarCharValue": v} if v is not None else {}) for v in vals]}
        header = row([n for n, _ in self.columns])
        everything = [header] + [row(r) for r in self.rows]
        start = int(NextToken or 0)
        page = everything[start:start + MaxResults]
        nxt = start + MaxResults
        out = {"ResultSet": {"Rows": page, "ResultSetMetadata": meta}}
        if nxt < len(everything):
            out["NextToken"] = str(nxt)
        return out


class FakeGlue:
    def __init__(self, dbs):
        self.dbs = dbs

    def get_paginator(self, name):
        glue = self
        class P:
            def paginate(self, DatabaseName=None):
                if name == "get_databases":
                    yield {"DatabaseList": [{"Name": d} for d in glue.dbs]}
                else:
                    yield {"TableList": glue.dbs[DatabaseName]}
        return P()


TABLES = {"sales": [
    {"Name": "orders", "TableType": "EXTERNAL_TABLE",
     "StorageDescriptor": {"Columns": [{"Name": "id", "Type": "int"},
                                       {"Name": "amount", "Type": "decimal(12,2)",
                                        "Comment": "net amount"}]},
     "PartitionKeys": [{"Name": "dt", "Type": "string"}]},
    {"Name": "v_orders", "TableType": "VIRTUAL_VIEW",
     "StorageDescriptor": {"Columns": [{"Name": "id", "Type": "int"}]}}]}


def conn(fake=None, sleepless=True):
    a = fake or FakeAthena()
    c = AthenaConnector("sid", dict(CFG), clients=(a, FakeGlue(TABLES)))
    return c, a


async def test_results_header_stripped_types_and_nulls():
    c, a = conn()
    r = await c.execute("SELECT 1", 100, 30)
    assert r["row_count"] == 3 and not r["truncated"]
    assert r["rows"][0] == [1, "10.10", "a", 0.5]        # int converted, decimal kept exact
    assert r["rows"][1][2] is None                        # NULL
    assert [x["name"] for x in r["columns"]] == ["id", "amount", "name", "ratio"]
    assert r["data_scanned_bytes"] == 2_000_000_000
    assert r["approx_cost_usd"] == pytest.approx(0.01)
    ctx = a.started[0]
    assert ctx["QueryExecutionContext"]["Database"] == "sales"
    assert ctx["WorkGroup"] == "primary"
    assert ctx["ResultConfiguration"]["OutputLocation"] == "s3://my-bucket/athena/"


async def test_truncation_exact_across_pages():
    c, a = conn()
    a.rows = [[str(i), "1.00", "x", "1.0"] for i in range(2500)]   # 3 pages of results
    r = await c.execute("SELECT 1", 2000, 30)
    assert r["row_count"] == 2000 and r["truncated"]
    r = await c.execute("SELECT 1", 2500, 30)
    assert r["row_count"] == 2500 and not r["truncated"]          # boundary
    assert r["rows"][0][0] == 0 and r["rows"][-1][0] == 2499      # no dup/missing at page seams


async def test_failed_query_surfaces_reason():
    c, a = conn()
    a.state_script = ["FAILED"]
    with pytest.raises(RuntimeError, match="SYNTAX_ERROR"):
        await c.execute("SELECT 1", 10, 30)


async def test_timeout_cancels_query():
    c, a = conn()
    a.state_script = ["RUNNING"]
    with pytest.raises(TimeoutError, match="cancelled"):
        await c.execute("SELECT 1", 10, 0)
    assert a.stopped == ["q1"]


async def test_introspect_from_glue_with_partitions_and_views():
    c, _ = conn()
    sc = await c.introspect()
    assert sc["default_schema"] == "sales"
    o = sc["schemas"]["sales"]["orders"]
    assert o["partition_keys"] == ["dt"] and [x["name"] for x in o["columns"]] == ["id", "amount", "dt"]
    assert o["columns"][1]["comment"] == "net amount"
    assert sc["schemas"]["sales"]["v_orders"]["kind"] == "view"


# ---- config validation and end-to-end through the tools -----------------------------
@pytest.mark.parametrize("patch,msg", [
    ({"region": "mars"}, "region"),
    ({"s3_output": "https://x"}, "s3://"),
    ({"database": "bad name;"}, "Glue database"),
    ({"workgroup": "a b"}, "workgroup"),
    ({"secret_access_key": ""}, "both"),
])
def test_config_validation(patch, msg):
    with pytest.raises(service.SourceError, match=msg):
        service.parse_config("athena", {**CFG, **patch})


def test_config_ok_and_iam_role_mode():
    assert service.parse_config("athena", CFG)["region"] == "ap-south-1"
    role = service.parse_config("athena", {**CFG, "access_key_id": "", "secret_access_key": ""})
    assert "access_key_id" not in role


@pytest_asyncio.fixture
async def env(monkeypatch):
    fake = FakeAthena()
    fake.rows = [["1", "10.10", "a", "0.5"]]
    monkeypatch.setattr("app.connectors.athena.clients_from_config",
                        lambda cfg: (fake, FakeGlue(TABLES)))
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.drop_all)
        await c.run_sync(Base.metadata.create_all)
    async with SessionLocal() as s:
        u = User(email="at@x.in", name="A", password_hash=hash_password("x"))
        s.add(u)
        await s.commit()
        fake.state_script = ["SUCCEEDED"]
        src = await service.create_source(s, u.id, "Lake", "athena", dict(CFG))
    current_user_id.set(u.id)
    yield {"src": src.id, "fake": fake, "user": u.id}


async def test_create_source_encrypts_keys_and_loads_schema(env):
    async with SessionLocal() as s:
        src = await s.get(DataSource, env["src"])
    assert b"super-secret-key" not in src.config_encrypted
    assert decrypt_config(src.config_encrypted, src.id)["secret_access_key"] == "super-secret-key"
    ov = await data.get_schema_overview(env["src"])
    assert {t["table"] for t in ov["tables"]} == {"orders", "v_orders"}


async def test_run_query_envelope_has_scan_info_and_partition_warning(env):
    r = await data.run_query(env["src"], "SELECT id FROM orders")
    assert r["dialect"] == "athena" and r["data_scanned_bytes"] == 2_000_000_000
    assert r["query_id"].startswith("q")
    assert any("partition" in w and "dt" in w for w in r["warnings"])
    ok = await data.run_query(env["src"], "SELECT id FROM orders WHERE dt = '2026-01-01'")
    assert not any("partition" in w for w in ok["warnings"])


async def test_writes_blocked_for_athena_dialect(env):
    for q in ("INSERT INTO orders VALUES (1)", "DROP TABLE orders",
              "CREATE TABLE x AS SELECT 1", "UNLOAD (SELECT 1) TO 's3://b/p'",
              "SELECT 1; SELECT 2"):
        with pytest.raises(ValueError):
            await data.run_query(env["src"], q)
    assert len(env["fake"].started) == 1        # only the connection-test query ever ran


async def test_failure_message_hides_secret(env):
    env["fake"].state_script = ["FAILED"]
    env["fake"].fail_reason = "denied for super-secret-key"
    with pytest.raises(ValueError) as e:
        await data.run_query(env["src"], "SELECT id FROM orders WHERE dt='x'")
    assert "super-secret-key" not in str(e.value)
    async with SessionLocal() as s:
        logs = (await s.execute(select(AuditLog).where(AuditLog.status == "error"))).scalars().all()
    assert logs and all("super-secret-key" not in (l.error or "") for l in logs)
