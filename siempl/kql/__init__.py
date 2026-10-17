"""KQL compiler and runner for siempl.

Compiles Microsoft Kusto Query Language (KQL) to DuckDB SQL and executes
queries securely (read-only, with row caps and timeouts).

Public API (contract defined in docs/ARCHITECTURE.md):
    KqlError           — parse, semantic, or runtime error
    CompiledQuery      — (sql, params, tables, columns)
    QueryResult        — (columns, rows, truncated, sql, elapsed_ms, tables)
    compile_kql(query) — parse + compile KQL to CompiledQuery
    run_kql(db, query) — compile + execute + log
    keywords()         — autocomplete keywords
    parse_kql(query)   — parse to AST (debugging, analysis)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..db import utcnow
from ._compiler import compile_pipeline
from ._executor import execute_compiled
from ._parser import KqlParseError, Pipeline, parse_kql

logger = logging.getLogger(__name__)


class KqlError(Exception):
    """Parse, semantic, or runtime error; message is user-presentable."""


@dataclass
class CompiledQuery:
    """A compiled KQL query ready for execution."""
    sql: str
    params: list
    tables: set[str]
    columns: list[str] | None


@dataclass
class QueryResult:
    """Result of executing a KQL query."""
    columns: list[str]
    rows: list[list]
    truncated: bool
    sql: str
    elapsed_ms: float
    tables: list[str]


def compile_kql(query: str, now: datetime | None = None) -> CompiledQuery:
    """Parse a KQL query string and compile it to DuckDB SQL.

    Args:
        query: KQL query string
        now: reference time for ago() / now() (defaults to utcnow() from siempl.db)

    Returns:
        CompiledQuery with sql, params, tables, columns

    Raises:
        KqlError: parse error or unsupported syntax
    """
    if not query or not query.strip():
        raise KqlError("empty query")
    try:
        pipeline = parse_kql(query)
        sql, params, tables = compile_pipeline(pipeline, now)
        return CompiledQuery(sql=sql, params=params, tables=tables, columns=None)
    except KqlParseError as e:
        raise KqlError(str(e)) from e
    except KqlError:
        raise
    except Exception as e:
        raise KqlError(f"compilation error: {e}") from e


def run_kql(
    db, query: str, *, limit: int = 10000, origin: str = "user",
    ref: str = "", log: bool = True,
) -> QueryResult:
    """Parse, compile, and execute a KQL query against the database.

    Args:
        db: Database instance
        query: KQL query string
        limit: maximum rows to return (default 10000)
        origin: "user" or "rule" (affects table_usage column)
        ref: reference string for query_log (e.g., rule_id)
        log: whether to write query_log + table_usage (default True)

    Returns:
        QueryResult with columns, rows, truncated, sql, elapsed_ms, tables

    Raises:
        KqlError: parse, compilation, or execution error
    """
    if not query or not query.strip():
        raise KqlError("empty query")

    t0 = time.monotonic()
    pipeline = None

    def _log_error(err: Exception) -> None:
        if not log:
            return
        try:
            tbls: list[str] = []
            if pipeline and pipeline.source:
                tbls = [pipeline.source.name] if hasattr(pipeline.source, 'name') else []
            db.execute(
                "INSERT INTO query_log(ts,origin,ref,tables,kql,rows_returned,elapsed_ms,error) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [utcnow(), origin, ref or "", tbls, query, 0,
                 (time.monotonic() - t0) * 1000, str(err)[:2000]],
            )
        except Exception:
            logger.debug("_log_error: ignored error", exc_info=True)

    try:
        pipeline = parse_kql(query)
        sql, params, tables = compile_pipeline(pipeline)
        cols, rows, truncated, elapsed = execute_compiled(
            db, sql, params, tables,
            limit=limit, origin=origin, ref=ref, log=log,
        )
        return QueryResult(
            columns=cols,
            rows=rows,
            truncated=truncated,
            sql=sql,
            elapsed_ms=elapsed,
            tables=list(tables) if tables else [],
        )
    except KqlParseError as e:
        # Parse/compile errors (incl. unknown tables) are logged too
        _log_error(e)
        raise KqlError(str(e)) from e
    except KqlError as e:
        _log_error(e)
        raise
    except Exception as e:
        _log_error(e)
        raise KqlError(str(e)) from e


def keywords() -> dict:
    """Return keyword/table/function lists for editor autocomplete.

    Returns:
        dict with keys: "tables", "operators", "functions"
    """
    from .. import schema
    from ._tokenizer import AGG_FUNCTIONS, KEYWORDS, PIPE_OPERATORS, SCALAR_FUNCTIONS

    return {
        "tables": sorted(schema.DATA_TABLES.keys()),
        "operators": sorted(PIPE_OPERATORS),
        "functions": sorted(AGG_FUNCTIONS | SCALAR_FUNCTIONS | {"iff", "iif", "case", "coalesce", "toscalar"}),
    }
