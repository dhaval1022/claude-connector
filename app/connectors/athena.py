"""Amazon Athena connector (boto3).

Schema discovery uses the Glue Data Catalog (free, fast). Queries run through the Athena API so
we get the query id, bytes scanned and the ability to cancel on timeout. Athena returns every
value as text, so decimals stay exact strings and integers are converted losslessly.

Cost control: Athena bills per TB scanned and cannot dry-run. We (1) always report bytes
scanned, (2) warn when a partitioned table is queried without its partition keys, (3) cancel
on timeout and (4) recommend a workgroup "data usage control" limit plus a read-only IAM role.
"""
import asyncio
import re
import time

from app.config import get_settings

REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}
PRICE_PER_TB_USD = 5.0   # us-east-1 list price; an estimate only


def _convert(value: str | None, athena_type: str):
    if value is None:
        return None
    t = athena_type.lower()
    try:
        if t in ("tinyint", "smallint", "integer", "int", "bigint"):
            return int(value)
        if t in ("double", "float", "real"):
            return float(value)
        if t == "boolean":
            return value.lower() == "true"
    except ValueError:
        return value
    return value   # decimal, varchar, date, timestamp, ...: exact text


def clients_from_config(cfg: dict):
    import boto3
    kwargs = {"region_name": cfg["region"]}
    if cfg.get("access_key_id"):
        kwargs.update(aws_access_key_id=cfg["access_key_id"],
                      aws_secret_access_key=cfg["secret_access_key"])
        if cfg.get("session_token"):
            kwargs["aws_session_token"] = cfg["session_token"]
    session = boto3.session.Session(**kwargs)   # else: default credential chain / IAM role
    return session.client("athena"), session.client("glue")


class AthenaConnector:
    dialect = "athena"
    engine_name = "athena"

    def __init__(self, source_id: str, cfg: dict, clients=None):
        self.source_id, self.cfg = source_id, cfg
        self._clients = clients          # injectable for tests
        self.database = cfg["database"]

    def _c(self):
        if self._clients is None:
            self._clients = clients_from_config(self.cfg)
        return self._clients

    # ---- blocking operations ----------------------------------------------------
    def _wait(self, sql: str, timeout_s: int):
        """Start a query and block until it finishes. Returns (athena, qid, execution, start)."""
        athena, _ = self._c()
        start = time.monotonic()
        qid = athena.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": self.database,
                                   "Catalog": self.cfg.get("catalog") or "AwsDataCatalog"},
            ResultConfiguration={"OutputLocation": self.cfg["s3_output"]},
            WorkGroup=self.cfg.get("workgroup") or "primary")["QueryExecutionId"]
        delay = 0.2
        while True:
            q = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
            state = q["Status"]["State"]
            if state in TERMINAL:
                break
            if time.monotonic() - start > timeout_s:
                athena.stop_query_execution(QueryExecutionId=qid)
                raise TimeoutError(f"Query exceeded the {timeout_s}s time limit and was "
                                   f"cancelled (Athena query {qid}).")
            time.sleep(delay)
            delay = min(delay * 1.5, 2.0)
        if state != "SUCCEEDED":
            reason = q["Status"].get("StateChangeReason", state)
            raise RuntimeError(f"Athena query {state.lower()}: {reason}")
        return athena, qid, q, start

    def _pages(self, athena, qid):
        """Yield (columns[(name,type)], rows[list]) per result page, header row removed."""
        token, first = None, True
        while True:
            kw = {"QueryExecutionId": qid, "MaxResults": 1000}
            if token:
                kw["NextToken"] = token
            page = athena.get_query_results(**kw)
            columns = [(c["Name"], c["Type"])
                       for c in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
            data_rows = page["ResultSet"]["Rows"]
            if first:
                data_rows = data_rows[1:]      # SELECT results begin with a header row
                first = False
            rows = [[_convert(d.get("VarCharValue"), t) for d, (_, t) in zip(r["Data"], columns)]
                    for r in data_rows]
            yield columns, rows
            token = page.get("NextToken")
            if not token:
                return

    def _execute(self, sql: str, max_rows: int, timeout_s: int) -> dict:
        athena, qid, q, start = self._wait(sql, timeout_s)
        columns, rows = None, []
        for columns, page_rows in self._pages(athena, qid):
            rows += page_rows
            if len(rows) > max_rows:
                break
        truncated = len(rows) > max_rows
        rows = rows[:max_rows]
        scanned = int(q.get("Statistics", {}).get("DataScannedInBytes", 0))
        return {
            "columns": [{"name": n, "type": t} for n, t in columns or []],
            "rows": rows, "row_count": len(rows), "truncated": truncated,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
            "query_id": qid, "data_scanned_bytes": scanned,
            "approx_cost_usd": round(scanned / 1e12 * PRICE_PER_TB_USD, 6),
        }

    def stream(self, sql: str, timeout_s: int, batch: int = 5000):
        athena, qid, _, _ = self._wait(sql, timeout_s)
        sent = False
        for columns, rows in self._pages(athena, qid):
            if not sent:
                yield {"columns": [n for n, _ in columns], "types": [t for _, t in columns]}
                sent = True
            if rows:
                yield {"rows": rows}

    def _introspect(self) -> dict:
        _, glue = self._c()
        budget = get_settings().max_schema_tables
        schemas: dict = {}
        dbs = [d["Name"] for p in glue.get_paginator("get_databases").paginate()
               for d in p["DatabaseList"]]
        for db in sorted(dbs):
            tables: dict = {}
            for page in glue.get_paginator("get_tables").paginate(DatabaseName=db):
                for t in page["TableList"]:
                    if budget <= 0:
                        break
                    budget -= 1
                    sd = t.get("StorageDescriptor") or {}
                    parts = t.get("PartitionKeys") or []
                    cols = [{"name": c["Name"], "type": c["Type"], "nullable": True,
                             **({"comment": c["Comment"]} if c.get("Comment") else {})}
                            for c in (sd.get("Columns") or []) + parts]
                    tables[t["Name"]] = {
                        "kind": "view" if t.get("TableType") == "VIRTUAL_VIEW" else "table",
                        "primary_key": [], "foreign_keys": [], "columns": cols,
                        "partition_keys": [p["Name"] for p in parts],
                        **({"notes": [t["Description"]]} if t.get("Description") else {})}
            if tables:
                schemas[db] = tables
        return {"default_schema": self.database, "schemas": schemas}

    # ---- async API ---------------------------------------------------------------
    async def execute(self, sql: str, max_rows: int, timeout_s: int) -> dict:
        return await asyncio.to_thread(self._execute, sql, max_rows, timeout_s)

    async def introspect(self) -> dict:
        return await asyncio.to_thread(self._introspect)

    async def test(self) -> None:
        await self.execute("SELECT 1", 1, 60)

    @staticmethod
    def dispose(source_id: str) -> None:
        pass
