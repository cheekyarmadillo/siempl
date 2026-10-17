"""Logs page encoding: JSON-safe cells, CSV/JSON bytes, and the export download response.

Not for: running queries (_logs_query.py) or route wiring (routes_logs.py).
Export contract: the file holds the same effective query as the screen (same time-range handling),
up to EXPORT_HARD_CAP rows. Truncation is reported in headers (X-Export-Truncated), never in the file,
so the CSV stays machine-readable.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import quote

from fastapi.responses import JSONResponse, Response

from ..audit import record as audit_record
from ..db import Database
from ..kql import KqlError
from ._logs_query import EXPORT_HARD_CAP, apply_time_range, event_tables, normalize_time_range, run_export

EXPORT_MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "json": "application/json; charset=utf-8"}


def json_cell(value: Any) -> Any:
    """Make one result cell JSON-safe: non-finite floats become null, dates become ISO strings."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def json_rows(rows: list[list]) -> list[list]:
    """Apply json_cell to every cell of every row."""
    return [[json_cell(cell) for cell in row] for row in rows]


def csv_bytes(columns: list[str], rows: list[list]) -> bytes:
    """RFC 4180 CSV: header row, then one row per result row. The csv module handles quoting."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    writer.writerows(json_rows(rows))
    return buf.getvalue().encode("utf-8")


def json_bytes(columns: list[str], rows: list[list]) -> bytes:
    """JSON array of objects keyed by column name (duplicate column names collapse to the last one)."""
    data = [dict(zip(columns, row, strict=False)) for row in json_rows(rows)]
    return json.dumps(data, default=str).encode("utf-8")


def export_filename(source: str, fmt: str, when: datetime | None = None) -> str:
    """siempl-<table>-<UTC timestamp>.<fmt>. The table part is reduced to identifier characters."""
    stamp = (when or datetime.now(UTC)).strftime("%Y%m%d-%H%M%S")
    name = re.sub(r"[^A-Za-z0-9_]", "", source)[:40] or "query"
    return f"siempl-{name}-{stamp}.{fmt}"


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _audit_export(db: Database, fmt: str, query: str, rows: int, truncated: bool) -> None:
    audit_record(
        db,
        "user:web",
        "query.export",
        "query",
        "",
        outcome="ok",
        details={"format": fmt, "rows": rows, "truncated": truncated, "query_preview": query[:200]},
    )


def export_response(db: Database, query: str, time_range: str, fmt: str) -> Response | JSONResponse:
    """Run the export for `query` with `time_range` and return the file, or a JSON error (400)."""
    fmt = (fmt or "csv").strip().lower()
    if fmt not in EXPORT_MEDIA_TYPES:
        return _error(400, "unsupported export format; use csv or json")
    query = (query or "").strip()
    if not query:
        return _error(400, "Empty query")
    try:
        time_range = normalize_time_range(time_range)
    except ValueError as exc:
        return _error(400, str(exc))
    prep = apply_time_range(query, time_range, event_tables())
    try:
        result = run_export(db, prep.kql)
    except KqlError as exc:
        return _error(400, str(exc))

    _audit_export(db, fmt, query, len(result.rows), result.truncated)
    body = csv_bytes(result.columns, result.rows) if fmt == "csv" else json_bytes(result.columns, result.rows)
    headers = {
        "Content-Disposition": f'attachment; filename="{export_filename(prep.source, fmt)}"',
        "X-Export-Rows": str(len(result.rows)),
        "X-Export-Truncated": "true" if result.truncated else "false",
        "X-Export-Row-Cap": str(EXPORT_HARD_CAP),
        "X-Time-Range-Applied": prep.time_range,
        "X-Time-Range-Note": quote(prep.note),
    }
    return Response(content=body, media_type=EXPORT_MEDIA_TYPES[fmt], headers=headers)
