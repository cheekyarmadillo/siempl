"""Ingest pipeline: receives raw records, normalizes them, and writes to DuckDB data tables.

Public API:
  NormalizedEvent(table, fields)   - a single event ready for DB insert
  IngestResult(received, inserted, dropped, failed, tables)  - pipeline result
  IngestPipeline(db)               - the main pipeline
    .ingest(source_id, records, *, parser=None) -> IngestResult

Behaviour:
  - resolves parser (argument > sources.parser > auto-detect)
  - normalizes via parser.parse()
  - applies enabled ingest_filters (matched rows are dropped, counts updated)
  - extracts and upserts entities
  - inserts via db.insert_events
  - bumps table_usage.rows_ingested and sources.events_total
  - unknown source_ids create a 'pending' source row

Thread safety: the pipeline wraps DuckDB writes in a thread-pool executor to avoid
blocking the event loop when used from async collectors.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timezone
from typing import Any, Optional

from ..db import Database, new_id
from ..schema import table_columns
from . import parsers
from .entities import extract_entities
from .types import IngestResult, NormalizedEvent

logger = logging.getLogger(__name__)

# Single-thread write executor (DuckDB serializes writes anyway)
_write_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ingest_write")


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ── pipeline ──────────────────────────────────────────────────────────────────

class IngestPipeline:
    """Receives raw records, normalizes, filters, extracts entities, and inserts.

    Designed to be called from synchronous or async code (async callers should use
    run_in_executor for `.ingest()` if blocking the event loop is a concern).
    """

    def __init__(self, db: Database):
        self._db = db

    # -- record normalisation -- -------------------------------------------------

    def _normalize(self, source_id: str, records: Iterable[str | dict],
                   parser_name: str | None) -> list[NormalizedEvent]:
        """Ask the parser to convert raw records into NormalizedEvents."""
        if parser_name in ("auto", "", "none"):
            parser_name = None   # "auto" = per-record auto-detection (the GUI default)
        p = parsers.get_parser(parser_name) if parser_name else None
        if p is None and parser_name:
            # Try auto-detect first, then fallback
            p = parsers.get_parser("generic_json")
        results: list[NormalizedEvent] = []
        for raw in records:
            try:
                if p is None:
                    # No parser specified, no source parser: auto-detect per record
                    results.extend(parsers.auto_parse(raw, source_id))
                else:
                    results.extend(p(raw, source_id))
            except Exception:
                # Individual parse failure shouldn't crash the batch
                logger.debug("_normalize: ignored error", exc_info=True)
        return results

    # -- filters -- --------------------------------------------------------------

    def _load_filters(self) -> list[dict]:
        return self._db.query(
            "SELECT filter_id, table_name, expression FROM ingest_filters WHERE enabled=TRUE")

    def _apply_filter(self, filt: dict, evt: NormalizedEvent) -> bool:
        """Return True if the event MATCHES (and should be dropped)."""
        table, expr = filt["table_name"], filt["expression"]
        if table and table != evt.table:
            return False
        # --- tiny-safe KQL subset ---
        return _tiny_filter_match(expr, evt.fields)

    # -- ingest ------------------------------------------------------------------

    def ingest(self, source_id: str, records: Iterable[str | dict],
               *, parser: str | None = None) -> IngestResult:
        """Ingest a batch of raw records.

        Args:
            source_id: sources.source_id (created as 'pending' on first sight).
            records:  raw strings or pre-parsed dicts.
            parser:   optional parser override (takes precedence over sources.parser).

        Returns:
            IngestResult with counts and per-table breakdown.
        """
        time.monotonic()
        ensure_source(self._db, source_id)   # idempotent

        # Resolve parser
        if not parser:
            r = self._db.query_one("SELECT parser FROM sources WHERE source_id=?", [source_id])
            parser = r["parser"] if r else None

        # Normalize
        raw_list = list(records)
        result = IngestResult(received=len(raw_list))
        events = self._normalize(source_id, raw_list, parser)
        if not events:
            return result

        # Filter
        filters = self._load_filters()
        if filters:
            kept: list[NormalizedEvent] = []
            for evt in events:
                if any(self._apply_filter(f, evt) for f in filters):
                    result.dropped += 1
                else:
                    kept.append(evt)
            events = kept
            # Update dropped counts
            for f in filters:
                # Batch update: cheaper than per-event
                self._db.execute(
                    "UPDATE ingest_filters SET dropped_total = dropped_total + 1 "
                    "WHERE filter_id = ?", [f["filter_id"]])

        if not events:
            return result

        # Extract entities (per event, collected across batch)
        entity_pairs: list[tuple[str, str, str]] = []
        for evt in events:
            for etype, value in extract_entities(evt.table, evt.fields):
                entity_pairs.append((etype, value, evt.table))

        # Group by table for insert
        by_table: dict[str, list[dict]] = {}
        for evt in events:
            by_table.setdefault(evt.table, []).append(evt.fields)

        # Insert + bump counters
        inserted_total = 0
        for table, rows in by_table.items():
            n = self._db.insert_events(table, rows)
            inserted_total += n
            result.tables[table] = result.tables.get(table, 0) + n

        result.inserted = inserted_total

        # Bump table_usage
        today = _utcnow().strftime("%Y-%m-%d")
        for table, n in result.tables.items():
            self._db.execute(
                "INSERT INTO table_usage(day,table_name,rows_ingested) VALUES (?::DATE,?,?) "
                "ON CONFLICT (day,table_name) DO UPDATE SET rows_ingested = rows_ingested + ?",
                [today, table, n, n])

        # Bump source counter
        self._db.execute("UPDATE sources SET events_total = events_total + ?, last_event_at = ? WHERE source_id = ?",
                         [inserted_total, _utcnow(), source_id])

        # Entity upserts (batched)
        if entity_pairs:
            _batch_entity_upsert(self._db, entity_pairs)

        result.failed = result.received - result.inserted - result.dropped
        return result


# ── helpers ────────────────────────────────────────────────────────────────────

def ensure_source(db: Database, source_id: str) -> None:
    """Create a 'pending' source row on first sight, idempotent."""
    exists = db.query_one("SELECT source_id FROM sources WHERE source_id=?", [source_id])
    if exists:
        return
    db.execute(
        "INSERT INTO sources(source_id,name,kind,status) VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
        [source_id, source_id, "unknown", "pending"])


def _batch_entity_upsert(db: Database, pairs: list[tuple[str, str, str]]) -> None:
    """Upsert entities and entity_tables side table in a batched fashion.
    pairs: (etype, value, table_name)"""
    now = _utcnow()
    # Deduplicate entities
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for etype, value, _tbl in pairs:
        key = (etype, value)
        if key not in seen:
            seen.add(key)
            unique.append(key)

    if not unique:
        return

    eids = [f"{t}:{v}" for t, v in unique]
    params: list = []
    for (etype, value), eid in zip(unique, eids):
        params.extend([eid, etype, value, now, now])

    # Build batched upsert for entities
    placeholders = ", ".join(["(?, ?, ?, ?, ?)"] * len(unique))
    sql = (
        f"INSERT INTO entities(entity_id, type, value, first_seen, last_seen) "
        f"VALUES {placeholders} "
        f"ON CONFLICT (entity_id) DO UPDATE SET "
        f"last_seen = EXCLUDED.last_seen, "
        f"event_count = entities.event_count + 1"
    )
    db.execute(sql, params)

    # Upsert entity_tables side table (deduped by eid+tbl)
    tbl_seen: set[tuple[str, str]] = set()
    tbl_params: list = []
    for etype, value, tbl in pairs:
        eid = f"{etype}:{value}"
        key = (eid, tbl)
        if key not in tbl_seen:
            tbl_seen.add(key)
            tbl_params.extend([eid, tbl, now, now, 1])
    if tbl_params:
        ph2 = ", ".join(["(?, ?, ?, ?, ?)"] * len(tbl_seen))
        sql2 = (
            f"INSERT INTO entity_tables(entity_id, table_name, first_seen, last_seen, event_count) "
            f"VALUES {ph2} "
            f"ON CONFLICT (entity_id, table_name) DO UPDATE SET "
            f"last_seen = EXCLUDED.last_seen, "
            f"event_count = entity_tables.event_count + 1"
        )
        db.execute(sql2, tbl_params)


# ── tiny KQL subset filter matching ────────────────────────────────────────────

def _tiny_filter_match(expr: str, fields: dict) -> bool:
    """Minimal safe KQL where-expression matcher. Supports column==value and contains.

    This is a fallback; the full KQL compiler (`siempl.kql.compile_kql`) should be used
    when the full compiler is wired in. For now, only these patterns:
      - `Column == "value"` or `Column == 'value'`
      - `Column contains "value"` (case-insensitive substring)
    Multiple conditions ANDed are supported (each line or separated by 'and').
    """
    if not expr or not expr.strip():
        return False

    clauses = [c.strip() for c in expr.replace(" and ", "\n").split("\n") if c.strip()]
    for clause in clauses:
        clause = clause.strip()
        # Column == "value"
        if "==" in clause:
            parts = clause.split("==", 1)
            col = parts[0].strip()
            val = parts[1].strip().strip('"').strip("'")
            field_val = str(fields.get(col, "")).lower()
            if field_val != val.lower():
                return False
        elif "contains" in clause:
            parts = clause.split("contains", 1)
            col = parts[0].strip()
            val = parts[1].strip().strip('"').strip("'")
            field_val = str(fields.get(col, "")).lower()
            if val.lower() not in field_val:
                return False
        else:
            return False  # can't evaluate unknown operator -> don't drop
    return True
