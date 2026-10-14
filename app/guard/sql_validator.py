"""Read-only SQL validation (defense in depth; engine-level read-only is applied too).

Accepts exactly one SELECT / UNION / WITH...SELECT statement. Rejects DML, DDL, SELECT INTO,
locking reads, dangerous functions, system credential tables and masked (PII) columns.
"""
import re
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

DENY_NODES = (exp.Insert, exp.Update, exp.Delete, exp.Merge, exp.Create, exp.Drop, exp.Alter,
              exp.Command, exp.Into, exp.Lock, exp.Set, exp.Use, exp.Transaction, exp.Commit,
              exp.Rollback, exp.Copy, exp.Grant, exp.TruncateTable, exp.LoadData, exp.Pragma)
for _n in ("Analyze", "Attach", "Detach", "Execute", "Declare", "Kill"):
    if hasattr(exp, _n):
        DENY_NODES += (getattr(exp, _n),)

DENY_FUNCTIONS = {
    "pg_sleep", "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "lo_import", "lo_export", "lo_get", "dblink", "dblink_exec", "set_config", "nextval",
    "setval", "pg_terminate_backend", "pg_cancel_backend", "load_file", "sleep", "benchmark",
    "get_lock", "release_lock", "openrowset", "opendatasource", "openquery", "openxml",
    "waitfor", "read_csv", "read_csv_auto", "read_parquet", "read_json", "read_json_auto",
    "read_text", "read_blob", "glob", "parquet_scan", "csv_scan", "sniff_csv", "query",
    "query_table", "getenv", "current_setting", "file", "url", "s3", "remote",
    "remotesecure", "mysql", "postgresql", "odbc", "jdbc", "hdfs", "cluster",
    "clusterallreplicas", "input", "executable",
}
DENY_FUNCTION_PREFIXES = ("xp_", "sp_", "pg_", "dbms_", "utl_", "lo_", "fn_", "sys_")
ALLOW_FUNCTIONS = {"pg_typeof", "pg_size_pretty"}
DENY_SCHEMAS = {"mysql", "performance_schema"}
DENY_TABLES = {"pg_shadow", "pg_authid", "pg_user_mapping", "pg_roles", "sql_logins",
               "syslogins", "sql_credentials", "server_principals", "database_principals"}


class QueryRejected(ValueError):
    """The SQL is not allowed; the message is safe to show to Claude/the user."""


@dataclass
class ValidatedQuery:
    sql: str                                  # SQL to execute (may have LIMIT injected)
    original_sql: str
    tables: list[tuple[str | None, str]] = field(default_factory=list)  # (schema, table)
    limit_injected: bool = False


def _func_name(node: exp.Expression) -> str:
    if isinstance(node, exp.Anonymous):
        return str(node.this).lower()
    return node.sql_name().lower()


def validate(sql: str, dialect: str, *, max_rows: int | None = None,
             masked_columns: set[str] | None = None,
             schema_columns: dict[str, set[str]] | None = None) -> ValidatedQuery:
    """schema_columns: {lower table name: {lower column names}} used to catch SELECT * that
    would expose a masked column."""
    text = (sql or "").strip()
    if not text:
        raise QueryRejected("Empty query.")
    try:
        statements = [s for s in sqlglot.parse(text, read=dialect) if s is not None]
    except SqlglotError as e:
        raise QueryRejected(f"Could not parse SQL for dialect '{dialect}': {str(e)[:300]}")
    if len(statements) != 1:
        raise QueryRejected("Exactly one statement is allowed (no multiple statements).")
    root = statements[0]
    if not isinstance(root, (exp.Select, exp.SetOperation if hasattr(exp, "SetOperation")
                             else exp.Union, exp.Subquery)):
        raise QueryRejected("Only read-only SELECT queries are allowed.")

    masked = {m.lower() for m in (masked_columns or set())}
    cte_names = {c.alias_or_name.lower() for c in root.find_all(exp.CTE)}
    tables: list[tuple[str | None, str]] = []

    for node in root.walk():
        node = node[0] if isinstance(node, tuple) else node
        if isinstance(node, DENY_NODES):
            raise QueryRejected(f"{type(node).__name__} statements are not allowed; "
                                "queries are read-only.")
        if isinstance(node, (exp.Func, exp.Anonymous)):
            name = _func_name(node)
            if name in DENY_FUNCTIONS or (name.startswith(DENY_FUNCTION_PREFIXES)
                                          and name not in ALLOW_FUNCTIONS):
                raise QueryRejected(f"Function '{name}' is not allowed.")
        if isinstance(node, exp.Table):
            if isinstance(node.this, (exp.Func, exp.Anonymous)):
                continue  # table function: its name was already checked above
            tname, schema = node.name.lower(), (node.db or "").lower() or None
            if re.search(r"[/\\]|^[a-z]+://|\.(csv|parquet|json|xlsx?|txt|db)$", tname):
                raise QueryRejected("Reading files by path is not allowed.")
            if tname in cte_names and not schema:
                continue
            if schema in DENY_SCHEMAS or tname in DENY_TABLES:
                raise QueryRejected(f"Access to system table '{node.name}' is not allowed.")
            tables.append((node.db or None, node.name))
        if isinstance(node, exp.Column) and masked and node.name.lower() in masked:
            raise QueryRejected(f"Column '{node.name}' is masked (restricted) and cannot be "
                                "queried. Choose other columns.")

    if masked:  # second pass: all tables are known now; COUNT(*) etc. are harmless
        stars = [n for n in root.find_all(exp.Star) if not isinstance(n.parent, exp.Func)]
        if stars:
            for _, t in tables:
                cols = (schema_columns or {}).get(t.lower())
                if cols is None or cols & masked:
                    raise QueryRejected(
                        f"SELECT * is not allowed on '{t}' because it contains masked "
                        "columns. List the columns explicitly.")

    final_sql, injected = text.rstrip().rstrip(";"), False
    if max_rows and isinstance(root, exp.Select) and not root.args.get("limit") \
            and not root.args.get("fetch") and not _has_top(root):
        try:
            final_sql = root.limit(max_rows + 1).sql(dialect=dialect)
            injected = True
        except SqlglotError:
            pass
    return ValidatedQuery(sql=final_sql, original_sql=text, tables=tables,
                          limit_injected=injected)


def _has_top(root: exp.Select) -> bool:
    return bool(root.args.get("kind") == "TOP" or root.args.get("top")
                or root.find(exp.Limit) is not None)
