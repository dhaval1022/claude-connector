"""Shared helpers for building dialect-correct SQL (via sqlglot) for the analysis tools.
Everything built here is still re-validated by the guard when executed through _run()."""
import re
from datetime import date

from sqlglot import exp

from app.sources.service import find_table

_NUM = re.compile(r"^(unsigned )?(tiny|small|medium|big)?int(eger)?\b|"
                  r"^(numeric|decimal|dec|number|float\d*|double|real|money|smallmoney|"
                  r"serial|bigserial)\b", re.I)
_TS = re.compile(r"timestamp|datetime|smalldatetime", re.I)
_TEXT = re.compile(r"char|text|string|clob|varchar|uuid", re.I)


def col_kind(type_str: str) -> str:
    t = (type_str or "").strip().lower()
    if t.startswith("interval"):
        return "other"
    if _TS.search(t):
        return "timestamp"
    if t.startswith("date"):
        return "date"
    if _NUM.search(t):
        return "numeric"
    if _TEXT.search(t):
        return "text"
    return "other"


def table_expr(schema: str | None, name: str) -> exp.Table:
    return exp.table_(name, db=schema, quoted=True)


def col(name: str) -> exp.Column:
    return exp.column(name, quoted=True)


def count_star() -> exp.Count:
    return exp.Count(this=exp.Star())


def find_column(info: dict, name: str) -> dict | None:
    for c in info["columns"]:
        if c["name"].lower() == name.strip().lower():
            return c
    return None


def require_column(info: dict, table: str, name: str) -> dict:
    c = find_column(info, name)
    if not c:
        import difflib
        close = difflib.get_close_matches(name, [x["name"] for x in info["columns"]], 3, 0.5)
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        raise ValueError(f"Column '{name}' not found in table '{table}'.{hint}")
    return c


def date_literal(iso: str, kind: str) -> exp.Expression:
    """A date literal that compares correctly against a column of the given kind."""
    date.fromisoformat(iso)  # validates; raises ValueError with a clear message
    if kind == "text":
        return exp.Literal.string(iso)
    return exp.Cast(this=exp.Literal.string(iso), to=exp.DataType.build("date"))


def day_expr(column: str, kind: str) -> exp.Expression:
    """Expression yielding the calendar day of a column, portable across engines."""
    c = col(column)
    if kind == "timestamp":
        return exp.Cast(this=c, to=exp.DataType.build("date"))
    if kind == "text":
        return exp.Substring(this=c, start=exp.Literal.number(1), length=exp.Literal.number(10))
    return c


def lookup(cache: dict, ref: str):
    found = find_table(cache, ref)
    if not found:
        raise ValueError(f"Table '{ref}' not found. Use search_schema or get_schema_overview.")
    return found
