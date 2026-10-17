"""DuckDB access layer. One process owns the DB file (collectors, scheduler, API all run in the
same process; see docs/ARCHITECTURE.md). Thread safety: use `db.cursor()` per thread/task and
hold `db.write_lock` around multi-statement writes.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import duckdb

from . import config, schema

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def new_id(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:12]


class Database:
    def __init__(self, path: str | None = None):
        self.path = str(path or config.db_path())
        self.conn = duckdb.connect(self.path)
        self.write_lock = threading.RLock()
        self.init_schema()

    # -- schema -------------------------------------------------------------------
    def init_schema(self) -> None:
        with self.write_lock:
            for t in schema.DATA_TABLES:
                self.conn.execute(schema.data_table_ddl(t))
            self.conn.execute(schema.META_DDL)
            for stmt in getattr(schema, "MIGRATIONS", []):
                try:
                    self.conn.execute(stmt)
                except Exception:   # already applied / table absent: migrations are best-effort
                    logger.debug("init_schema: ignored error", exc_info=True)
            from .migrations_alerts import migrate_alerts
            migrate_alerts(self)
            self._seed_defaults()
            # DuckDB 1.5.x cannot replay a WAL containing ALTER TABLE ADD COLUMN on these tables after an
            # unclean exit (INTERNAL Error ... GetDefaultDatabase). Folding the WAL into the file right after
            # schema changes means a kill -9 can only ever lose plain row writes, never the whole database.
            self.conn.execute("CHECKPOINT")

    def _seed_defaults(self) -> None:
        # Global default agent policy: everything starts conservative.
        self.conn.execute(
            "INSERT OR IGNORE INTO agent_policy VALUES ('triage','global','*','recommend',TRUE,TRUE,FALSE,TRUE)")

    # -- cursors / helpers --------------------------------------------------------
    def cursor(self) -> duckdb.DuckDBPyConnection:
        return self.conn.cursor()

    def execute(self, sql: str, params: list | tuple | None = None) -> duckdb.DuckDBPyConnection:
        with self.write_lock:
            return self.conn.cursor().execute(sql, params or [])

    def query(self, sql: str, params: list | tuple | None = None) -> list[dict[str, Any]]:
        cur = self.conn.cursor().execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def query_one(self, sql: str, params: list | tuple | None = None) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- settings -----------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        r = self.query_one("SELECT value FROM settings WHERE key=?", [key])
        if r is not None:
            return json.loads(r["value"]) if isinstance(r["value"], str) else r["value"]
        return config.DEFAULT_SETTINGS.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        self.execute("INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES (?,?,now())",
                     [key, json.dumps(value)])

    # DuckDB parameter count must stay sane in the parameterized fallback.
    INSERT_CHUNK = 1000

    # -- event insert -------------------------------------------------------------
    def insert_events(self, table: str, rows: Iterable[dict[str, Any]]) -> int:
        """Insert normalized event dicts into a data table. Unknown keys go into Extra.
        Missing columns become NULL. IngestTime defaults to now. Returns rows inserted.

        Bulk path: spill rows to a temp NDJSON file and `INSERT ... BY NAME SELECT
        * FROM read_json(...)`. DuckDB's Python parameter binding is very slow at
        volume (~500 rows/s) — even as a multi-row VALUES statement each `?` bind
        round-trips the C extension; `read_json` bulk-loads at ~80k rows/s.
        Falls back to chunked parameterized INSERTs if the json path fails
        (extension missing, mixed-type columns, etc.).
        """
        cols = [c[0] for c in schema.table_columns(table)]
        colset = set(cols)
        now = utcnow()
        batch = []
        for r in rows:
            r = dict(r)
            extra = r.pop("Extra", None)
            extra = dict(extra) if isinstance(extra, dict) else ({} if extra is None else {"_extra": extra})
            for k in [k for k in r if k not in colset]:
                extra[k] = r.pop(k)
            r["Extra"] = json.dumps(extra, default=str) if extra else None
            r.setdefault("IngestTime", now)
            if r.get("TimeGenerated") is None:
                r["TimeGenerated"] = r["IngestTime"]
            batch.append({c: r.get(c) for c in cols})
        if not batch:
            return 0
        inserted = self._bulk_insert_ndjson(table, batch)
        if inserted is None:
            self._insert_rows_parameterized(table, cols, [list(r.values()) for r in batch])
            return len(batch)
        return inserted

    def _bulk_insert_ndjson(self, table: str, batch: list[dict[str, Any]]) -> int | None:
        """Insert via NDJSON spill + read_json. Returns row count or None on failure."""
        import os
        import tempfile
        fd, path = tempfile.mkstemp(prefix="siempl-ingest-", suffix=".ndjson")
        try:
            with os.fdopen(fd, "w") as f:
                dump = json.dumps
                for r in batch:
                    f.write(dump(r, default=str))
                    f.write("\n")
            with self.write_lock:
                self.conn.cursor().execute(
                    f"INSERT INTO \"{table}\" BY NAME SELECT * FROM "
                    f"read_json('{path}', format='newline_delimited')")
            return len(batch)
        except Exception:
            return None
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _insert_rows_parameterized(self, table: str, cols: list, batch: list) -> None:
        col_list = ",".join(chr(34) + c + chr(34) for c in cols)
        row_ph = "(" + ",".join("?" * len(cols)) + ")"
        with self.write_lock:
            for start in range(0, len(batch), self.INSERT_CHUNK):
                chunk = batch[start:start + self.INSERT_CHUNK]
                q = f'INSERT INTO "{table}" ({col_list}) VALUES ' + ",".join(row_ph for _ in chunk)
                params = []
                for row in chunk:
                    params.extend(row)
                self.conn.cursor().execute(q, params)

    def close(self) -> None:
        self.conn.close()


_default: Database | None = None


def get_db() -> Database:
    global _default
    if _default is None:
        _default = Database()
    return _default
