"""KQL query executor: compiles + runs KQL securely against DuckDB.

Security guarantees:
  - Rejects non-SELECT queries (read-only enforcement)
  - Result row cap (limit param)
  - Statement timeout via thread + connection interrupt
  - All errors mapped to KqlError with user-presentable messages
"""
from __future__ import annotations

import logging
import threading
import time

from ..db import Database, utcnow

logger = logging.getLogger(__name__)

# Maximum allowed execution time for a KQL query (seconds)
MAX_QUERY_SECONDS = 30


def _enforce_select_only(sql: str) -> None:
    """Reject any SQL that isn't a SELECT / WITH ... SELECT."""
    from . import KqlError  # noqa: PLC0415  # lazy to avoid circular import
    stripped = sql.strip().upper()
    if not stripped.startswith(("SELECT", "WITH", "EXPLAIN", "DESCRIBE")):
        raise KqlError("only read-only SELECT queries are allowed (KQL has no write operators)")


def _run_with_timeout(db: Database, sql: str, params: list, limit: int) -> tuple[list[str], list[list]]:
    """Execute SQL with a statement timeout via thread interrupt.

    Runs the query in a background thread; the main thread waits with a
    timeout. On timeout, calls conn.interrupt() to cancel the query.
    """
    from . import KqlError  # noqa: PLC0415  # lazy to avoid circular import
    result_holder: dict = {"cols": [], "rows": [], "error": None, "done": False}
    lock = threading.Lock()

    def _execute():
        try:
            cur = db.conn.cursor()
            cur.execute(sql, params)
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = [list(r) for r in cur.fetchmany(limit + 1)]
            with lock:
                result_holder["cols"] = cols
                result_holder["rows"] = rows
                result_holder["done"] = True
        except Exception as e:
            with lock:
                result_holder["error"] = str(e)
                result_holder["done"] = True

    thread = threading.Thread(target=_execute, daemon=True)
    thread.start()
    thread.join(timeout=MAX_QUERY_SECONDS)

    if thread.is_alive():
        # Timeout: interrupt DuckDB
        try:
            db.conn.interrupt()
        except Exception:
            logger.debug("_run_with_timeout: ignored error", exc_info=True)
        thread.join(timeout=3)
        if thread.is_alive():
            raise KqlError("query timed out and could not be cancelled")
        raise KqlError(f"query timed out after {MAX_QUERY_SECONDS}s")

    with lock:
        if result_holder["error"]:
            raise KqlError(result_holder["error"])
        return result_holder["cols"], result_holder["rows"]


def execute_compiled(
    db: Database,
    sql: str,
    params: list,
    tables: set[str],
    *,
    limit: int = 10000,
    origin: str = "user",
    ref: str = "",
    log: bool = True,
) -> tuple[list[str], list[list], bool, float]:
    """Execute compiled SQL against the database with safety constraints.

    Returns (columns, rows, truncated, elapsed_ms).
    """
    _enforce_select_only(sql)

    t0 = time.monotonic()
    cols, rows = _run_with_timeout(db, sql, params, limit)
    elapsed_ms = (time.monotonic() - t0) * 1000

    truncated = len(rows) > limit
    if truncated:
        rows = rows[:limit]

    # Log query
    if log:
        try:
            db.execute(
                "INSERT INTO query_log(ts,origin,ref,tables,kql,rows_returned,elapsed_ms) "
                "VALUES (?,?,?,?,?,?,?)",
                [utcnow(), origin, ref or "", list(tables) if tables else [], sql,
                 len(rows), elapsed_ms],
            )
            # Bump table_usage
            col = "rule_queries" if origin == "rule" else "user_queries"
            for t in tables:
                if not t:
                    continue
                db.execute(
                    f"INSERT INTO table_usage(day,table_name,rows_ingested,bytes_ingested,"
                    f"rule_queries,user_queries,alerts_generated) VALUES "
                    f"(CAST(now() AS DATE),?,0,0,"
                    f"CASE WHEN '{col}'='rule_queries' THEN 1 ELSE 0 END,"
                    f"CASE WHEN '{col}'='user_queries' THEN 1 ELSE 0 END,0) "
                    f"ON CONFLICT (day,table_name) DO UPDATE SET "
                    f"{col} = table_usage.{col} + 1",
                    [t],
                )
        except Exception:
            logger.debug("execute_compiled: ignored error", exc_info=True)  # Logging failures shouldn't break the query

    return cols, rows, truncated, elapsed_ms
