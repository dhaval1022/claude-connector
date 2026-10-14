import pytest

from app.guard.sql_validator import QueryRejected, validate

ALLOWED = [
    ("postgres", "SELECT * FROM orders"),
    ("postgres", "select o.id, sum(o.amt) from sales.orders o group by 1 order by 2 desc"),
    ("postgres", "WITH a AS (SELECT 1 AS x) SELECT * FROM a"),
    ("postgres", "SELECT 1 UNION ALL SELECT 2"),
    ("postgres", "SELECT date_trunc('month', d), count(*) FROM t GROUP BY 1;"),
    ("postgres", "SELECT pg_typeof(1)"),
    ("mysql", "SELECT `a`, COUNT(*) FROM `db`.`t` GROUP BY `a` LIMIT 10"),
    ("tsql", "SELECT TOP 10 name FROM dbo.products ORDER BY name"),
    ("tsql", "WITH c AS (SELECT id FROM dbo.t) SELECT COUNT(*) FROM c"),
    ("sqlite", "SELECT a, b FROM t WHERE a IN (SELECT a FROM u)"),
    ("postgres", "SELECT a FROM information_schema.columns"),
]

REJECTED = [
    ("postgres", "INSERT INTO t VALUES (1)"),
    ("postgres", "UPDATE t SET a=1"),
    ("postgres", "DELETE FROM t"),
    ("postgres", "DROP TABLE t"),
    ("postgres", "TRUNCATE TABLE t"),
    ("postgres", "CREATE TABLE x AS SELECT 1"),
    ("postgres", "SELECT 1; DROP TABLE t"),
    ("postgres", "SELECT 1; SELECT 2"),
    ("postgres", "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"),
    ("postgres", "SELECT * FROM t FOR UPDATE"),
    ("postgres", "SELECT * INTO newt FROM t"),
    ("tsql", "SELECT * INTO newt FROM t"),
    ("tsql", "EXEC xp_cmdshell 'dir'"),
    ("tsql", "EXEC sp_who"),
    ("tsql", "SELECT * FROM OPENROWSET('SQLNCLI','x','select 1')"),
    ("postgres", "SELECT pg_sleep(100)"),
    ("postgres", "SELECT pg_read_file('/etc/passwd')"),
    ("postgres", "SELECT nextval('s')"),
    ("postgres", "SELECT * FROM pg_shadow"),
    ("postgres", "SELECT * FROM pg_catalog.pg_authid"),
    ("mysql", "SELECT SLEEP(10)"),
    ("mysql", "SELECT * FROM mysql.user"),
    ("mysql", "SELECT LOAD_FILE('/etc/passwd')"),
    ("tsql", "SELECT * FROM sys.sql_logins"),
    ("postgres", "COPY t TO '/tmp/x'"),
    ("postgres", "SET search_path = x"),
    ("postgres", "BEGIN"),
    ("postgres", "CALL do_things()"),
    ("postgres", "GRANT ALL ON t TO u"),
    ("postgres", ""),
    ("postgres", "SELEC FROM"),
    ("duckdb", "SELECT * FROM read_csv('/etc/passwd')"),
    ("duckdb", "SELECT * FROM read_parquet('s3://x/y')"),
    ("duckdb", "COPY (SELECT 1) TO 'x.csv'"),
    ("duckdb", "SELECT * FROM '/etc/hosts'"),
    ("duckdb", "SELECT * FROM 'data.csv'"),
    ("duckdb", "SELECT * FROM 'C:\\Users\\x\\secret'"),
    ("duckdb", "SELECT * FROM 's3://bucket/key'"),
]


@pytest.mark.parametrize("dialect,sql", ALLOWED)
def test_allowed(dialect, sql):
    assert validate(sql, dialect).sql


@pytest.mark.parametrize("dialect,sql", REJECTED)
def test_rejected(dialect, sql):
    with pytest.raises(QueryRejected):
        validate(sql, dialect)


def test_comment_cannot_smuggle_second_statement():
    with pytest.raises(QueryRejected):
        validate("SELECT 1 /* x */; /* y */ DELETE FROM t", "postgres")


def test_cte_name_not_treated_as_table():
    v = validate("WITH a AS (SELECT 1 x) SELECT * FROM a JOIN real_t r ON 1=1", "postgres")
    assert v.tables == [(None, "real_t")]


def test_limit_injected_when_missing():
    v = validate("SELECT a FROM t", "postgres", max_rows=500)
    assert v.limit_injected and "LIMIT 501" in v.sql


def test_limit_injected_tsql_uses_top():
    v = validate("SELECT a FROM t", "tsql", max_rows=500)
    assert v.limit_injected and "TOP 501" in v.sql


def test_existing_limit_kept():
    v = validate("SELECT a FROM t LIMIT 5", "postgres", max_rows=500)
    assert not v.limit_injected and v.sql.endswith("LIMIT 5")


def test_existing_top_kept():
    v = validate("SELECT TOP 5 a FROM t", "tsql", max_rows=500)
    assert not v.limit_injected


def test_masked_column_blocked_everywhere():
    for q in ["SELECT phone FROM c", "SELECT count(*) FROM c WHERE phone = '1'",
              "SELECT x.phone AS p FROM c x", "SELECT a FROM c ORDER BY phone"]:
        with pytest.raises(QueryRejected):
            validate(q, "postgres", masked_columns={"Phone"})


def test_star_blocked_when_table_has_masked_columns():
    cols = {"c": {"id", "phone"}, "o": {"id", "amt"}}
    with pytest.raises(QueryRejected):
        validate("SELECT * FROM c", "postgres", masked_columns={"phone"}, schema_columns=cols)
    assert validate("SELECT * FROM o", "postgres", masked_columns={"phone"},
                    schema_columns=cols)
    with pytest.raises(QueryRejected):  # unknown table: be conservative
        validate("SELECT * FROM mystery", "postgres", masked_columns={"phone"},
                 schema_columns=cols)
