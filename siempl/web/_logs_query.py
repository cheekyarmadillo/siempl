"""Logs page query preparation: time-range filter, display limit, and the KQL runs behind the page.

Owns the rules that turn what the user typed plus the time-range picker into the KQL that actually runs.
Not for: HTTP handling (routes_logs.py) or CSV/JSON encoding (_logs_export.py).

Time range rule (decided 2026-10-14): the range is inserted as `| where TimeGenerated > ago(<range>)`
directly after the leading table name, so it filters raw rows BEFORE any summarize/take/project. It is
only applied when that table is an event table in DATA_TABLES (all of them carry TimeGenerated). For
`alerts`, `entities`, `let` statements, or unknown names the query runs unchanged and a note says why.
"""
from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass

from ..db import Database
from ..kql import KqlError, QueryResult, compile_kql, run_kql
from ..schema import DATA_TABLES

DISPLAY_LIMIT_DEFAULT = 50
EXPORT_HARD_CAP = 100_000
TIME_RANGES = ("15m", "1h", "6h", "24h", "7d")

# Leading table name of a pipeline, skipping blank lines and // comments. Only a bare name followed by
# '|' or end of text matches, so `let x = ...` is not mistaken for a table.
_LEADING_TABLE = re.compile(r"\A(?:\s|//[^\n]*)*([A-Za-z_]\w*)(?=\s*(?:\||\Z))")


@dataclass(frozen=True)
class PreparedQuery:
    """KQL to run, plus what the time-range picker did to it."""

    kql: str
    time_range: str  # range actually applied ("" when none was applied)
    note: str  # why a requested range was not applied ("" otherwise)
    source: str  # leading table name ("" when none was found)


def normalize_time_range(value: str | None) -> str:
    """Return a supported time range ("" = all time) or raise ValueError."""
    tr = (value or "").strip()
    if tr and tr not in TIME_RANGES:
        raise ValueError(f"unknown time range '{tr}'; use one of {', '.join(TIME_RANGES)} or leave it empty")
    return tr


def event_tables() -> frozenset[str]:
    """Tables that carry TimeGenerated. Every DATA_TABLES entry does (COMMON_COLUMNS)."""
    return frozenset(DATA_TABLES)


def apply_time_range(query: str, time_range: str, tables: Collection[str]) -> PreparedQuery:
    """Insert the time filter after the leading table, or explain why it was not applied.

    Args:
        query: KQL text (already stripped).
        time_range: one of TIME_RANGES, or "" for all time.
        tables: names that have a TimeGenerated column.
    """
    match = _LEADING_TABLE.match(query)
    source = match.group(1) if match else ""
    if not time_range:
        return PreparedQuery(query, "", "", source)
    if match is None:
        return PreparedQuery(query, "", "time range not applied: the query does not start with a table name "
                                        "(let statements are not filtered)", "")
    if source not in tables:
        return PreparedQuery(query, "", f"time range not applied: {source} is not an event table "
                                        "with TimeGenerated", source)
    cut = match.end(1)
    kql = f"{query[:cut]} | where TimeGenerated > ago({time_range}){query[cut:]}"
    return PreparedQuery(kql, time_range, "", source)


def has_explicit_take(kql: str) -> bool:
    """True when the query already limits its own rows (take / top / limit)."""
    try:
        compiled = compile_kql(kql)
    except KqlError:
        # Invalid query: append nothing and let the real run report the error.
        return True
    return "LIMIT" in compiled.sql.upper()


def with_display_limit(kql: str, limit: int | None) -> tuple[str, int | None]:
    """Append `| take N` for the results table unless the query has its own take. Returns (kql, applied)."""
    if not limit or limit <= 0 or has_explicit_take(kql):
        return kql, None
    return f"{kql} | take {limit}", limit


def run_display(db: Database, kql: str, limit: int | None) -> tuple[QueryResult, int | None]:
    """Run for the results table. Returns (result, display limit applied or None).

    Raises KqlError for every failure; the message is the user-facing text.
    """
    text, applied = with_display_limit(kql, limit)
    return run_kql(db, text, origin="user", log=True), applied


def run_export(db: Database, kql: str) -> QueryResult:
    """Run the full query for export: no display limit appended, executor cap = EXPORT_HARD_CAP.

    The executor cap (not a `take`) is what makes `truncated` honest: it fetches cap+1 rows.
    """
    return run_kql(db, kql, limit=EXPORT_HARD_CAP, origin="user", log=True)
