"""Ingestion sources page: CRUD, filters, retention, collector control, parser auto-detect."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..audit import record as audit_record
from ..db import Database, new_id
from ..schema import DATA_TABLES
from ._ingestion_overview import build_overview

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

_KQL = None
try:
    import siempl.kql as _KQL  # type:ignore[import-untyped]
except ImportError:
    pass
_INGEST = None
try:
    import siempl.ingest as _INGEST  # type:ignore[import-untyped]
except ImportError:
    pass


def _ctx(request: Request, page: str, title: str, **extra):
    return {"request": request, "page": page, "title": title, **extra}


def _has(module) -> bool:
    return module is not None


def _ensure_tables(db: Database):
    """Ensure ingest_filters and table_retention tables exist."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS ingest_filters (
            filter_id VARCHAR PRIMARY KEY,
            table_name VARCHAR,
            expression VARCHAR,
            description VARCHAR,
            enabled BOOLEAN DEFAULT FALSE,
            origin VARCHAR,
            created_at TIMESTAMP DEFAULT now(),
            dropped_total BIGINT DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS table_retention (
            table_name VARCHAR PRIMARY KEY,
            retention_days INTEGER
        )
    """)


def _list_parsers(db):
    parsers = []
    try:
        rows = db.query("SELECT name FROM parsers ORDER BY name")
        parsers = [r["name"] for r in rows]
    except Exception:
        logger.debug("_list_parsers: ignored error", exc_info=True)
    builtins = []
    if _has(_INGEST):
        try:
            builtins = list(_INGEST.list_parsers().keys())
        except Exception:
            builtins = []
    return sorted(set(builtins + parsers + ["auto"]))


def _get_collector_manager(request: Request):
    if hasattr(request.app.state, "collector_manager"):
        return request.app.state.collector_manager
    return None


def _validate_source_update(db, body):
    """Server-side validation for source update/create.
    Returns (errors dict or None, cleaned fields dict)."""
    errors = {}
    config = body.get("config") or {}
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except json.JSONDecodeError:
            errors["config"] = "Invalid JSON"
            config = {}
    kind = body.get("kind", "http")

    if kind == "syslog" and isinstance(config, dict):
        udp = config.get("udp_port", 5514)
        tcp = config.get("tcp_port", 5514)
        for field, val in [("udp_port", udp), ("tcp_port", tcp)]:
            try:
                v = int(val)
                if not (1024 <= v <= 65535):
                    errors[field] = "Port must be 1024-65535"
            except (TypeError, ValueError):
                errors[field] = "Port must be an integer"

    if kind == "file" and isinstance(config, dict):
        path = config.get("path", "")
        if path and not os.path.exists(path):
            errors["path"] = "File path does not exist"

    target = body.get("target_table", "")
    if target and target not in DATA_TABLES:
        errors["target_table"] = f"Unknown table: {target}"

    parser = body.get("parser", "")
    if parser and parser != "auto":
        known = _list_parsers(db)
        if parser not in known:
            errors["parser"] = f"Unknown parser: {parser}"

    return (errors if errors else None), body


def build_router(db: Database) -> APIRouter:
    r = APIRouter()
    _ensure_tables(db)

    # ------------------------------------------------------------------ pages
    @r.get("/ingestion", response_class=HTMLResponse)
    async def ingestion_page(request: Request):
        sources = db.query("SELECT * FROM sources ORDER BY last_event_at DESC NULLS LAST")
        filters = db.query("SELECT * FROM ingest_filters ORDER BY created_at DESC")
        retention = {r["table_name"]: r["retention_days"] for r in db.query("SELECT * FROM table_retention")}
        parsers = _list_parsers(db)
        table_stats = []
        for tname in DATA_TABLES:
            cnt = db.query_one(f'SELECT count(*) AS c FROM "{tname}"')
            table_stats.append({"name": tname, "rows": int(cnt["c"]) if cnt else 0,
                                "retention_days": retention.get(tname)})

        # Live collector status
        cm = _get_collector_manager(request)
        collector_status = cm.status() if cm else {}
        for s in sources:
            s["running"] = collector_status.get(s["source_id"], {}).get("running", False)
            s["last_error"] = collector_status.get(s["source_id"], {}).get("last_error")
        overview = build_overview(db, request.query_params.get("range"),
                                  frozenset(s["source_id"] for s in sources if s["last_error"]))

        # Build endpoint hints from request
        host = request.headers.get("host", "127.0.0.1:8765")
        return templates.TemplateResponse(
            request, "ingestion.html",
            _ctx(request, "ingestion", "Ingestion",
                 sources=sources, table_stats=table_stats, filters=filters, overview=overview,
                 parsers=parsers, tables=[k for k in DATA_TABLES],
                 host=host))

    # ------------------------------------------------------------------ API: sources
    @r.post("/api/sources")
    async def api_source_create(request: Request):
        try:
            body = await request.json()
            errs, _ = _validate_source_update(db, body)
            if errs:
                return JSONResponse({"error": "Validation failed", "details": errs}, status_code=400)

            sid = body.get("source_id", "").strip() or new_id("src_")
            kind = body.get("kind", "http")
            config = body.get("config") or {}
            db.execute(
                "INSERT INTO sources(source_id,name,kind,parser,target_table,status,config,created_at) VALUES (?,?,?,?,?,?,?,now())",
                [sid,
                 body.get("name", sid).strip(),
                 kind,
                 body.get("parser", "auto"),
                 body.get("target_table", "GenericEvents"),
                 body.get("status", "active"),
                 json.dumps(config) if isinstance(config, dict) else str(config)])
            audit_record(db, "user:web", "source.create", "source", sid,
                         details={"kind": kind, "name": body.get("name", "")})
            return {"ok": True, "source_id": sid}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.put("/api/sources/{source_id}")
    async def api_source_update(source_id: str, request: Request):
        try:
            body = await request.json()
            allowed = {"name", "parser", "target_table", "status", "config"}
            fields = {k: v for k, v in body.items() if k in allowed}
            if not fields:
                return JSONResponse({"error": "No updatable fields"}, status_code=400)

            # Validation
            current = db.query_one("SELECT kind, config FROM sources WHERE source_id=?", [source_id])
            if not current:
                return JSONResponse({"error": "Source not found"}, status_code=404)

            # Merge current kind into body for validation (kind not updatable but needed)
            validate_body = dict(current)
            validate_body.update(body)
            errs, _ = _validate_source_update(db, validate_body)
            if errs:
                return JSONResponse({"error": "Validation failed", "details": errs}, status_code=400)

            if "config" in fields and isinstance(fields["config"], dict):
                fields["config"] = json.dumps(fields["config"])

            # Detect if config changed to know if restart is needed
            restart = False
            if "config" in fields:
                old_config = current.get("config") or {}
                if isinstance(old_config, str):
                    try:
                        old_config = json.loads(old_config)
                    except json.JSONDecodeError:
                        old_config = {}
                if old_config != body.get("config"):
                    restart = True

            set_clause = ", ".join(f"{k}=?" for k in fields)
            vals = list(fields.values()) + [source_id]
            db.execute(f"UPDATE sources SET {set_clause} WHERE source_id=?", vals)
            audit_record(db, "user:web", "source.update", "source", source_id,
                         details={"fields": list(body.keys())})

            # Restart collector if it's running and config changed
            cm = _get_collector_manager(request)
            if restart and cm:
                stat = cm.status()
                if source_id in stat and stat[source_id].get("running"):
                    cm.stop(source_id)
                    cm.start(source_id)

            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ------------------------------------------------------------------ start / stop / status
    @r.post("/api/sources/{source_id}/start")
    async def api_source_start(source_id: str, request: Request):
        try:
            cm = _get_collector_manager(request)
            if cm is None:
                return JSONResponse({"error": "CollectorManager not available"}, status_code=503)

            src = db.query_one("SELECT kind, status FROM sources WHERE source_id=?", [source_id])
            if not src:
                return JSONResponse({"error": "Source not found"}, status_code=404)

            result = cm.start(source_id)
            if result.get("ok"):
                db.execute("UPDATE sources SET status='active' WHERE source_id=?", [source_id])
                audit_record(db, "user:web", "source.start", "source", source_id)
            return result
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/sources/{source_id}/stop")
    async def api_source_stop(source_id: str, request: Request):
        try:
            cm = _get_collector_manager(request)
            if cm is None:
                return JSONResponse({"error": "CollectorManager not available"}, status_code=503)

            src = db.query_one("SELECT source_id FROM sources WHERE source_id=?", [source_id])
            if not src:
                return JSONResponse({"error": "Source not found"}, status_code=404)

            result = cm.stop(source_id)
            if result.get("ok"):
                audit_record(db, "user:web", "source.stop", "source", source_id)
            return result
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.get("/api/collectors/status")
    async def api_collectors_status(request: Request):
        cm = _get_collector_manager(request)
        if cm is None:
            return JSONResponse({"error": "CollectorManager not available"}, status_code=503)
        return {"ok": True, "collectors": cm.status()}

    # ------------------------------------------------------------------ pause / resume
    @r.post("/api/sources/{source_id}/pause")
    async def api_source_pause(source_id: str, request: Request):
        try:
            cm = _get_collector_manager(request)
            if cm:
                cm.stop(source_id)
            db.execute("UPDATE sources SET status='paused' WHERE source_id=?", [source_id])
            audit_record(db, "user:web", "source.pause", "source", source_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/sources/{source_id}/resume")
    async def api_source_resume(source_id: str, request: Request):
        try:
            src = db.query_one("SELECT kind, status FROM sources WHERE source_id=?", [source_id])
            if not src:
                return JSONResponse({"error": "Source not found"}, status_code=404)

            if src.get("kind") in ("syslog", "file"):
                cm = _get_collector_manager(request)
                if cm:
                    cm.start(source_id)
            db.execute("UPDATE sources SET status='active' WHERE source_id=?", [source_id])
            audit_record(db, "user:web", "source.resume", "source", source_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ------------------------------------------------------------------ delete (stop first)
    @r.post("/api/sources/{source_id}/delete")
    async def api_source_delete(source_id: str, request: Request):
        try:
            cm = _get_collector_manager(request)
            if cm:
                cm.stop(source_id)
            db.execute("DELETE FROM sources WHERE source_id=?", [source_id])
            audit_record(db, "user:web", "source.delete", "source", source_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ------------------------------------------------------------------ API: filters
    @r.post("/api/filters")
    async def api_filter_create(request: Request):
        try:
            body = await request.json()
            fid = new_id("flt_")
            db.execute(
                "INSERT INTO ingest_filters(filter_id,table_name,expression,description,enabled,origin) VALUES (?,?,?,?,?,?)",
                [fid, body.get("table_name", ""), body.get("expression", ""),
                 body.get("description", ""), bool(body.get("enabled", False)), "manual"])
            audit_record(db, "user:web", "filter.create", "filter", fid)
            return {"ok": True, "filter_id": fid}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.put("/api/filters/{filter_id}")
    async def api_filter_update(filter_id: str, request: Request):
        try:
            body = await request.json()
            allowed = {"table_name", "expression", "description", "enabled"}
            fields = {k: v for k, v in body.items() if k in allowed}
            if not fields:
                return JSONResponse({"error": "No updatable fields"}, status_code=400)
            set_clause = ", ".join(f"{k}=?" for k in fields)
            vals = list(fields.values()) + [filter_id]
            db.execute(f"UPDATE ingest_filters SET {set_clause} WHERE filter_id=?", vals)
            audit_record(db, "user:web", "filter.update", "filter", filter_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/filters/{filter_id}/delete")
    async def api_filter_delete(filter_id: str):
        try:
            db.execute("DELETE FROM ingest_filters WHERE filter_id=?", [filter_id])
            audit_record(db, "user:web", "filter.delete", "filter", filter_id)
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/filters/test")
    async def api_filter_test(request: Request):
        """Test a KQL drop-filter expression: show how many rows would match."""
        if not _has(_KQL):
            return JSONResponse({"error": "KQL module not available"}, status_code=503)
        try:
            body = await request.json()
            table = body.get("table_name", "")
            expr = body.get("expression", "").strip()
            if not table or not expr:
                return JSONResponse({"error": "table_name and expression required"}, status_code=400)
            query = f'{table} | where {expr} | summarize count()'
            result = _KQL.run_kql(db, query, origin="user", log=False)
            row_count = result.rows[0][0] if result.rows else 0
            return {"ok": True, "row_count": row_count, "table": table, "expression": expr}
        except _KQL.KqlError as e:
            return JSONResponse({"error": str(e), "ok": False}, status_code=400)
        except Exception as e:
            return JSONResponse({"error": str(e), "ok": False}, status_code=500)

    # ------------------------------------------------------------------ API: retention
    @r.post("/api/ingestion/retention")
    async def api_retention_update(request: Request):
        try:
            body = await request.json()
            db.execute(
                "INSERT OR REPLACE INTO table_retention(table_name,retention_days) VALUES (?,?)",
                [body["table_name"], int(body["retention_days"])])
            audit_record(db, "user:web", "retention.set", "table", body["table_name"],
                         details={"days": int(body["retention_days"])})
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ------------------------------------------------------------------ API: detect parser from sample
    @r.post("/api/sources/detect-parser")
    async def api_detect_parser(request: Request):
        """Given sample log lines, try to detect parser and preview parsed fields."""
        if not _has(_INGEST):
            return JSONResponse({"error": "ingest module not available"}, status_code=503)
        try:
            body = await request.json()
            lines = body.get("samples", [])
            if not lines:
                return JSONResponse({"error": "No samples"}, status_code=400)
            from ..ingest._detect import detect_parsers
            return {"ok": True, "candidates": detect_parsers(lines)}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    return r
