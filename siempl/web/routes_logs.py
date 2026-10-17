"""Logs routes: overrides legacy /logs from routes.py.

Page (/logs), JSON query API (/api/query) and export (/api/export, GET and POST).
Query preparation (time range, display limit) lives in _logs_query.py; encoding and export responses in
_logs_export.py. Not for: KQL semantics or CSV layout.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import duckdb
from fastapi import APIRouter, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..db import Database
from ..kql import KqlError, keywords
from ..schema import DATA_TABLES, table_columns
from ._logs_export import export_response, json_rows
from ._logs_query import (
    DISPLAY_LIMIT_DEFAULT,
    PreparedQuery,
    apply_time_range,
    event_tables,
    normalize_time_range,
    run_display,
)

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Page state keys: time_range is the picker value the user (or deep link) asked for; result.time_range is
# what was actually applied; time_range_note says why a requested range was not applied.
_EMPTY_PAGE_STATE = {
    "result": None,
    "error": "",
    "time_range": "",
    "time_range_note": "",
}


@dataclass(frozen=True)
class _QueryRequest:
    query: str
    time_range: str
    limit: int | None


def _ctx(request, page, title, **extra):
    from .routes import SEVERITY_CLASS, _mod_state
    return {
        "request": request,
        "page": page,
        "title": title,
        "modules": _mod_state(),
        "severity_class": SEVERITY_CLASS,
        **extra,
    }


def _parse_query_body(body) -> _QueryRequest:
    """Validate the JSON body of /api/query. Raises ValueError with the user-facing message."""
    if not isinstance(body, dict):
        raise ValueError("request body must be a JSON object")
    query = str(body.get("query") or "").strip()
    if not query:
        raise ValueError("Empty query")
    limit = body.get("limit")
    if not isinstance(limit, int) or isinstance(limit, bool):
        limit = DISPLAY_LIMIT_DEFAULT
    return _QueryRequest(query, normalize_time_range(body.get("time_range")), limit if limit > 0 else None)


def result_payload(query: str, requested_tr: str, result, applied: int | None, prep: PreparedQuery) -> dict:
    """JSON shape shared by /api/query and the server-rendered page (the page embeds it for chart/pivot)."""
    return {
        "query": query,
        "requested_time_range": requested_tr,
        "columns": result.columns,
        "rows": json_rows(result.rows),
        "truncated": result.truncated,
        "sql": result.sql,
        "elapsed_ms": result.elapsed_ms,
        "tables": result.tables,
        "limit_applied": applied,
        "time_range": prep.time_range,
        "time_range_note": prep.note,
    }


def _page_state(db: Database, q: str, display_limit: int | None, tr: str) -> dict:
    """Server-side run for /logs?q=... Errors are returned as text for the page, never raised."""
    try:
        requested = normalize_time_range(tr)
    except ValueError as exc:
        return {**_EMPTY_PAGE_STATE, "error": str(exc)}
    query = q.strip()
    if not query:
        return {**_EMPTY_PAGE_STATE, "time_range": requested}
    prep = apply_time_range(query, requested, event_tables())
    try:
        result, applied = run_display(db, prep.kql, display_limit)
    except KqlError as exc:
        return {**_EMPTY_PAGE_STATE, "error": str(exc), "time_range": requested, "time_range_note": prep.note}
    payload = result_payload(query, requested, result, applied, prep)
    return {**_EMPTY_PAGE_STATE, "result": payload, "time_range": requested, "time_range_note": prep.note}


def _tables_info() -> list[dict]:
    return [
        {
            "name": tname,
            "description": meta.get("description", ""),
            "columns": [c[0] for c in table_columns(tname)],
        }
        for tname, meta in DATA_TABLES.items()
    ]


def _query_history(db: Database) -> list[dict]:
    try:
        return db.query("SELECT * FROM query_log ORDER BY ts DESC LIMIT 50")
    except duckdb.Error:
        logger.debug("logs_page: query_log unreadable", exc_info=True)
        return []


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/logs", response_class=HTMLResponse)
    async def logs_page(
        request: Request,
        q: str = "",
        limit: int = DISPLAY_LIMIT_DEFAULT,
        limit_off: int = 0,
        tr: str = "",
    ):
        display_limit = None if limit_off else limit
        state = await run_in_threadpool(_page_state, db, q, display_limit, tr)
        return templates.TemplateResponse(
            request,
            "logs.html",
            _ctx(
                request,
                "logs",
                "Logs",
                tables_info=_tables_info(),
                query_history=_query_history(db),
                kql_keywords=keywords(),
                initial_query=q,
                display_limit=display_limit,
                default_limit=DISPLAY_LIMIT_DEFAULT,
                **state,
            ),
            headers={"Cache-Control": "no-cache"},
        )

    @r.post("/api/query")
    async def api_query(request: Request):
        try:
            req = _parse_query_body(await request.json())
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        prep = apply_time_range(req.query, req.time_range, event_tables())
        try:
            result, applied = await run_in_threadpool(run_display, db, prep.kql, req.limit)
        except KqlError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        return result_payload(req.query, req.time_range, result, applied, prep)

    @r.get("/api/export")
    async def api_export_get(
        query: str = Query(""),
        format: str = Query("csv"),
        time_range: str = Query(""),
    ):
        return await run_in_threadpool(export_response, db, query, time_range, format)

    @r.post("/api/export")
    async def api_export_post(request: Request):
        try:
            body = await request.json()
        except ValueError as exc:
            return JSONResponse({"error": f"invalid JSON body: {exc}"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "request body must be a JSON object"}, status_code=400)
        return await run_in_threadpool(
            export_response,
            db,
            str(body.get("query") or ""),
            str(body.get("time_range") or ""),
            str(body.get("format") or "csv"),
        )

    return r
