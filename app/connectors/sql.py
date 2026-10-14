"""SQLAlchemy-backed connector (PostgreSQL, MySQL/MariaDB, SQL Server; SQLite for dev/tests).

Sync drivers run in worker threads. Every query runs in a read-only, always-rolled-back
transaction with a statement timeout; rows are fetched with a cap so truncation is exact."""
import asyncio
import threading
import time
from datetime import date, datetime, time as dtime
from decimal import Decimal

from sqlalchemy import create_engine, inspect
from sqlalchemy.engine import URL, Engine

from app.config import get_settings

DIALECTS = {"postgres": "postgres", "mysql": "mysql", "mssql": "tsql", "sqlite": "sqlite"}
DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "mssql": 1433}
_ENGINES: dict[str, Engine] = {}
_LOCK = threading.Lock()


def build_url(engine: str, cfg: dict) -> URL:
    if engine == "sqlite":
        return URL.create("sqlite", database=cfg["database"])
    port = int(cfg.get("port") or DEFAULT_PORTS[engine])
    common = dict(username=cfg.get("username"), password=cfg.get("password"),
                  host=cfg["host"], port=port, database=cfg.get("database"))
    if engine == "postgres":
        return URL.create("postgresql+psycopg2", **common,
                          query={"sslmode": cfg.get("sslmode") or "prefer"})
    if engine == "mysql":
        return URL.create("mysql+pymysql", **common, query={"charset": "utf8mb4"})
    if engine == "mssql":
        q = {"driver": cfg.get("driver") or "ODBC Driver 18 for SQL Server",
             "ApplicationIntent": "ReadOnly",
             "TrustServerCertificate": "yes" if cfg.get("trust_server_cert") else "no"}
        return URL.create("mssql+pyodbc", **common, query=q)
    raise ValueError(f"Unsupported engine '{engine}'")


def _jsonable(v):
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, Decimal):
        return str(v)          # exact: never round money through float
    if isinstance(v, float):
        return v
    if isinstance(v, datetime):
        return v.isoformat()   # tz offset included when the driver provides one
    if isinstance(v, (date, dtime)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return f"<binary {len(bytes(v))} bytes>"
    return str(v)


def _type_name(values: list) -> str:
    for v in values:
        if v is not None:
            return {Decimal: "decimal", datetime: "datetime"}.get(type(v), type(v).__name__)
    return "unknown"


class SqlConnector:
    def __init__(self, source_id: str, engine_name: str, cfg: dict):
        self.source_id, self.engine_name, self.cfg = source_id, engine_name, cfg
        self.dialect = DIALECTS[engine_name]

    def _engine(self) -> Engine:
        with _LOCK:
            eng = _ENGINES.get(self.source_id)
            if eng is None:
                eng = create_engine(build_url(self.engine_name, self.cfg), pool_size=2,
                                    max_overflow=2, pool_pre_ping=True, pool_recycle=1800,
                                    pool_timeout=10)
                _ENGINES[self.source_id] = eng
            return eng

    @staticmethod
    def dispose(source_id: str) -> None:
        with _LOCK:
            eng = _ENGINES.pop(source_id, None)
        if eng:
            eng.dispose()

    # ---- read-only session setup -------------------------------------------------
    def _prepare(self, conn, timeout_s: int) -> None:
        ms = int(timeout_s * 1000)
        n = self.engine_name
        if n == "postgres":
            conn.exec_driver_sql("SET TRANSACTION READ ONLY")
            conn.exec_driver_sql(f"SET LOCAL statement_timeout = {ms}")
        elif n == "mysql":
            conn.exec_driver_sql("SET SESSION TRANSACTION READ ONLY")
            try:
                conn.exec_driver_sql(f"SET SESSION MAX_EXECUTION_TIME = {ms}")
            except Exception:  # MariaDB uses max_statement_time (seconds)
                conn.exec_driver_sql(f"SET SESSION max_statement_time = {timeout_s}")
        elif n == "mssql":
            conn.connection.dbapi_connection.timeout = timeout_s
        elif n == "sqlite":
            conn.exec_driver_sql("PRAGMA query_only = ON")
            deadline = time.monotonic() + timeout_s
            conn.connection.dbapi_connection.set_progress_handler(
                lambda: 1 if time.monotonic() > deadline else 0, 10_000)

    # ---- operations (blocking; call via the async wrappers) ----------------------
    def _execute(self, sql: str, max_rows: int, timeout_s: int) -> dict:
        start = time.monotonic()
        with self._engine().connect() as conn:
            try:
                self._prepare(conn, timeout_s)
                result = conn.exec_driver_sql(sql)
                if not result.returns_rows:
                    raise ValueError("Statement did not return rows.")
                columns = list(result.keys())
                raw = result.fetchmany(max_rows + 1)
            finally:
                conn.rollback()  # never commit anything
        truncated = len(raw) > max_rows
        raw = raw[:max_rows]
        cols_vals = list(zip(*raw)) if raw else [[] for _ in columns]
        return {
            "columns": [{"name": c, "type": _type_name(list(v))}
                        for c, v in zip(columns, cols_vals)],
            "rows": [[_jsonable(v) for v in r] for r in raw],
            "row_count": len(raw),
            "truncated": truncated,
            "elapsed_ms": int((time.monotonic() - start) * 1000),
        }

    def stream(self, sql: str, timeout_s: int, batch: int = 5000):
        """Blocking generator for exports: {"columns", "types"} then {"rows"} batches.
        Server-side cursors where the driver supports them, so memory stays flat."""
        with self._engine().connect() as conn:
            try:
                conn = conn.execution_options(stream_results=True)
                self._prepare(conn, timeout_s)
                result = conn.exec_driver_sql(sql)
                if not result.returns_rows:
                    raise ValueError("Statement did not return rows.")
                yield {"columns": list(result.keys()), "types": None}
                while True:
                    rows = result.fetchmany(batch)
                    if not rows:
                        break
                    yield {"rows": rows}
            finally:
                conn.rollback()

    def _introspect(self) -> dict:
        insp = inspect(self._engine())
        system = {"information_schema", "pg_catalog", "pg_toast", "sys", "mysql",
                  "performance_schema", "INFORMATION_SCHEMA"}
        out: dict = {}
        budget = get_settings().max_schema_tables
        default_schema = insp.default_schema_name
        for schema in insp.get_schema_names():
            if schema in system or schema.startswith("pg_temp") or schema.startswith("db_"):
                continue
            tables: dict = {}
            names = [(t, "table") for t in insp.get_table_names(schema=schema)]
            try:
                names += [(v, "view") for v in insp.get_view_names(schema=schema)]
            except NotImplementedError:
                pass
            for name, kind in names:
                if budget <= 0:
                    break
                budget -= 1
                try:
                    cols = insp.get_columns(name, schema=schema)
                    pk = insp.get_pk_constraint(name, schema=schema).get(
                        "constrained_columns", [])
                    fks = [{"columns": f["constrained_columns"],
                            "ref_schema": f.get("referred_schema"),
                            "ref_table": f["referred_table"],
                            "ref_columns": f["referred_columns"]}
                           for f in insp.get_foreign_keys(name, schema=schema)]
                except Exception:
                    continue  # skip tables we cannot introspect (permissions)
                tables[name] = {
                    "kind": kind, "primary_key": pk, "foreign_keys": fks,
                    "columns": [{"name": c["name"], "type": str(c["type"]),
                                 "nullable": bool(c.get("nullable", True))} for c in cols]}
            if tables:
                out[schema] = tables
        return {"default_schema": default_schema, "schemas": out}

    # ---- async API -----------------------------------------------------------------
    async def execute(self, sql: str, max_rows: int, timeout_s: int) -> dict:
        return await asyncio.to_thread(self._execute, sql, max_rows, timeout_s)

    async def introspect(self) -> dict:
        return await asyncio.to_thread(self._introspect)

    async def test(self) -> None:
        await self.execute("SELECT 1", 1, 15)


def make_connector(source_id: str, engine_name: str, cfg: dict) -> SqlConnector:
    if engine_name == "sqlite" and not get_settings().enable_sqlite:
        raise ValueError("SQLite is disabled.")
    if engine_name not in DIALECTS:
        raise ValueError(f"Unsupported engine '{engine_name}'")
    return SqlConnector(source_id, engine_name, cfg)
