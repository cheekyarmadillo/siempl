"""KQL rule query execution via the siempl.kql compiler.

All rule queries are canonical KQL text compiled by siempl.kql.compile_kql
and executed as DuckDB SQL.  The raw SQL fallback is removed.

Time-window convention: rule queries include their own `TimeGenerated > ago(Nm)`
predicate.  The scheduler calls this function and never rewrites queries.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime

from ..db import Database
from ..kql import KqlError, QueryResult, compile_kql

logger = logging.getLogger(__name__)

_SQL_FROM_RE = re.compile(r'\bFROM\s+"?([A-Za-z_]\w*)"?', re.IGNORECASE)


def _run_sql_rule(db: Database, query: str, *, rule_id: str, limit: int, log: bool,
                  now: datetime | None, lookback_minutes: int) -> QueryResult:
    """Run a pySigma-generated DuckDB SELECT with the rule's time window applied."""
    from datetime import timedelta

    from ..db import utcnow
    from ..schema import DATA_TABLES
    q = query.strip().rstrip(";").strip()
    import duckdb
    try:
        stmts = duckdb.extract_statements(q)
    except Exception as e:
        raise KqlError(f"sql rule does not parse: {e}") from e
    if len(stmts) != 1 or stmts[0].type != duckdb.StatementType.SELECT:
        raise KqlError("sql rule must be a single SELECT statement")
    tables = [t for t in dict.fromkeys(_SQL_FROM_RE.findall(q)) if t in DATA_TABLES]
    if not tables:
        raise KqlError("sql rule must select from one of the data tables")
    since = (now or utcnow()) - timedelta(minutes=max(1, int(lookback_minutes or 5)))
    sql = f'SELECT * FROM ({q}) AS _r WHERE _r."TimeGenerated" > ?'
    t0 = time.monotonic()
    try:
        cur = db.cursor()
        cur.execute(sql, [since])
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [list(r) for r in cur.fetchmany(limit + 1)]
    except Exception as e:
        raise KqlError(str(e)) from e
    truncated = len(rows) > limit
    rows = rows[:limit]
    elapsed_ms = (time.monotonic() - t0) * 1000
    if log:
        try:
            db.execute("INSERT INTO query_log(ts,origin,ref,tables,kql,rows_returned,elapsed_ms) VALUES (?,?,?,?,?,?,?)",
                       [utcnow(), "rule", rule_id, tables, query, len(rows), elapsed_ms])
            for tbl in tables:
                db.execute("INSERT INTO table_usage(day,table_name,rows_ingested,bytes_ingested,rule_queries,user_queries,alerts_generated) "
                           "VALUES (CAST(now() AS DATE),?,0,0,1,0,0) ON CONFLICT (day,table_name) DO UPDATE SET rule_queries = table_usage.rule_queries + 1",
                           [tbl])
        except Exception:
            logger.debug("_run_sql_rule: ignored error", exc_info=True)
    return QueryResult(columns=cols, rows=rows, truncated=truncated, sql=sql, elapsed_ms=elapsed_ms, tables=tables)


def run_rule_query(db: Database, query: str, *, rule_id: str = "",
                   limit: int = 10000, log: bool = True,
                   now: datetime | None = None, query_lang: str = "kql",
                   lookback_minutes: int = 5) -> QueryResult:
    """Compile a KQL rule query to DuckDB SQL and execute it.

    Args:
        db: Database instance
        query: KQL query string (the canonical rule language)
        rule_id: rule identifier for query_log
        limit: maximum rows to return
        log: whether to write query_log + table_usage
        now: override for ago()/now() (useful for backfill testing against
             historical synthetic data)

    Returns:
        QueryResult with columns, rows, truncated, sql, elapsed_ms, tables

    Raises:
        KqlError: parse, compilation, or execution error
    """
    if not query or not query.strip():
        raise KqlError("empty query")
    if (query_lang or "kql").lower() == "sql":
        return _run_sql_rule(db, query, rule_id=rule_id, limit=limit, log=log, now=now,
                             lookback_minutes=lookback_minutes)

    t0 = time.monotonic()
    compiled = None
    tables: list[str] = []
    try:
        compiled = compile_kql(query, now=now)
        tables = list(compiled.tables) if compiled.tables else []
    except KqlError:
        raise
    except Exception as e:
        raise KqlError(str(e)) from e

    try:
        cur = db.cursor()
        cur.execute(compiled.sql, compiled.params)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [list(r) for r in cur.fetchmany(limit + 1)]
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]
        elapsed_ms = (time.monotonic() - t0) * 1000

        if log:
            try:
                from ..db import utcnow
                db.execute(
                    "INSERT INTO query_log(ts,origin,ref,tables,kql,rows_returned,elapsed_ms) "
                    "VALUES (?,?,?,?,?,?,?)",
                    [utcnow(), "rule", rule_id, tables, query, len(rows), elapsed_ms],
                )
                for tbl in tables:
                    db.execute(
                        "INSERT INTO table_usage(day,table_name,rows_ingested,bytes_ingested,"
                        "rule_queries,user_queries,alerts_generated) VALUES "
                        "(CAST(now() AS DATE),?,0,0,1,0,0) "
                        "ON CONFLICT (day,table_name) DO UPDATE SET "
                        "rule_queries = table_usage.rule_queries + 1",
                        [tbl],
                    )
            except Exception:
                logger.debug("run_rule_query: ignored error", exc_info=True)

        return QueryResult(columns=cols, rows=rows, truncated=truncated,
                           sql=compiled.sql, elapsed_ms=elapsed_ms, tables=tables)
    except Exception as e:
        raise KqlError(str(e)) from e
