"""Entities routes: overrides legacy /entities and /entities/{id} from routes.py.

Uses {entity_id:path} converter so slashes/spaces/colons/backslashes in entity IDs work.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..audit import record as audit_record
from ..db import Database, utcnow
from ..schema import DATA_TABLES, ENTITY_COLUMNS

logger = logging.getLogger(__name__)

TEMPLATES_DIR = __import__("pathlib", fromlist=["Path"]).Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

try:
    import siempl.kql as _KQL  # type: ignore[import-untyped]
except ImportError:
    _KQL = None  # type: ignore[misc]


def _has(module) -> bool:
    return module is not None


def _ctx(request: Request, page: str, title: str, **extra):
    from .routes import SEVERITY_CLASS, _mod_state
    return {
        "request": request,
        "page": page,
        "title": title,
        "modules": _mod_state(),
        "severity_class": SEVERITY_CLASS,
        **extra,
    }


def _reltime(dt: datetime | None) -> str:
    if not dt:
        return "—"
    diff = (utcnow() - dt).total_seconds()
    if diff < 60:
        return "just now"
    if diff < 3600:
        return f"{int(diff / 60)}m ago"
    if diff < 86400:
        return f"{int(diff / 3600)}h ago"
    return f"{int(diff / 86400)}d ago"


def _relevant_columns(etype: str) -> list[tuple[str, str]]:
    """Return [(table, column), ...] for a given entity type."""
    cols = [col for col, t in ENTITY_COLUMNS.items() if t == etype]
    out = []
    for table, meta in DATA_TABLES.items():
        table_cols = {c[0] for c in meta.get("columns", [])}
        table_cols |= {c[0] for c in __import__("siempl.schema", fromlist=["COMMON_COLUMNS"]).COMMON_COLUMNS}
        for col in cols:
            if col in table_cols:
                out.append((table, col))
    return out


# ------------------------------------------------------------------
# Helpers: fast entity_tables + alerts
# ------------------------------------------------------------------

def _ensure_entity_tables(db: Database) -> None:
    """Create side table if not present; lazy backfill from existing data."""
    try:
        db.execute("SELECT 1 FROM entity_tables LIMIT 0")
    except Exception:
        from ..schema import META_DDL
        db.execute(META_DDL.split("CREATE TABLE IF NOT EXISTS entity_tables")[1].split(";")[0])
    # Check if empty -> trigger backfill via EntityStore
    cnt = db.query_one("SELECT COUNT(*) AS c FROM entity_tables")
    if cnt and int(cnt["c"]) == 0:
        from ..entities import EntityStore
        EntityStore(db).backfill_entity_tables()


def _fetch_entity_tables_fast(db: Database, entity_ids: list[str]) -> dict[str, set[str]]:
    """Map entity_id -> set of table names via entity_tables side table (single query)."""
    if not entity_ids:
        return {}
    placeholders = ",".join("?" * len(entity_ids))
    rows = db.query(
        f"SELECT entity_id, table_name FROM entity_tables WHERE entity_id IN ({placeholders})",
        entity_ids,
    )
    result: dict[str, set[str]] = {}
    for r in rows:
        result.setdefault(r["entity_id"], set()).add(r["table_name"])
    return result


def _fetch_entity_alerts_fast(db: Database, entity_ids: list[str]) -> dict[str, list[dict]]:
    """Map entity_id -> list of alert dicts via JSON path scan (single query per type)."""
    if not entity_ids:
        return {}
    result: dict[str, list[dict]] = {eid: [] for eid in entity_ids}
    # Build a temp table of entity_id -> (type:value) for JSON matching
    # DuckDB can use json_extract in WHERE with string patterns; we do one pass.
    # Simpler: scan all alerts with entities != NULL once, match in Python.
    # This is still O(alerts) not O(entities*alerts).
    try:
        alert_rows = db.query(
            "SELECT alert_id, title, severity, status, entities FROM alerts WHERE entities IS NOT NULL"
        )
    except Exception:
        return result

    # Build a set of normalized lookups for fast check
    lookups = set(entity_ids)

    for a in alert_rows:
        ents = a.get("entities")
        if isinstance(ents, str):
            try:
                ents = json.loads(ents)
            except Exception:
                ents = []
        if not isinstance(ents, list):
            continue
        for ent in ents:
            eid = f"{ent.get('type','')}:{ent.get('value','').lower()}"
            if eid in lookups:
                result.setdefault(eid, []).append(dict(a))
                break  # one alert per entity max in this pass
    return result


# ------------------------------------------------------------------
# Router
# ------------------------------------------------------------------

def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    # --------------------------------------------------------------
    # Entities list
    # --------------------------------------------------------------
    @r.get("/entities", response_class=HTMLResponse)
    async def entities_page(
        request: Request,
        etype: str = "",
        q: str = "",
        table_filter: str = "",
        has_alerts: str = "",
        sort: str = "alert_count DESC",
    ):
        entities: list[dict] = []
        total = 0
        try:
            where = ["1=1"]
            params: list = []
            if etype:
                where.append("type = ?")
                params.append(etype)
            if q:
                where.append("value ILIKE ?")
                params.append(f"%{q}%")
            w = " AND ".join(where)

            allowed_sort = {
                "alert_count DESC", "alert_count ASC",
                "event_count DESC", "event_count ASC",
                "reputation DESC", "reputation ASC",
                "last_seen DESC", "last_seen ASC",
                "value ASC", "value DESC",
            }
            order = sort if sort in allowed_sort else "alert_count DESC"

            entities = db.query(
                f"SELECT * FROM entities WHERE {w} ORDER BY {order} LIMIT 200",
                params,
            )
            total = int(db.query_one(f"SELECT count(*) AS c FROM entities WHERE {w}", params)["c"])  # type: ignore[index]
        except Exception:
            logger.debug("entities_page: ignored error", exc_info=True)

        entity_types: list[str] = []
        try:
            entity_types = [r["type"] for r in db.query("SELECT DISTINCT type FROM entities ORDER BY type")]
        except Exception:
            logger.debug("entities_page: ignored error", exc_info=True)

        # Ensure side table exists and is backfilled
        _ensure_entity_tables(db)

        # Fast lookup via side table + single-pass alerts
        eids = [e["entity_id"] for e in entities]
        entity_tables = _fetch_entity_tables_fast(db, eids)
        entity_alerts = _fetch_entity_alerts_fast(db, eids)

        # Filter by table / has_alerts in Python
        filtered = []
        for e in entities:
            eid = e["entity_id"]
            tables = sorted(entity_tables.get(eid, set()))
            alerts = entity_alerts.get(eid, [])
            if table_filter and table_filter not in tables:
                continue
            if has_alerts and not alerts:
                continue
            e["_tables"] = tables
            e["_alerts"] = alerts
            e["_reltime"] = _reltime(e.get("last_seen"))
            filtered.append(e)

        display_total = len(filtered)
        data_table_names = sorted(DATA_TABLES.keys())

        return templates.TemplateResponse(
            request,
            "entities.html",
            _ctx(
                request,
                "entities",
                "Entities",
                entities=filtered,
                total=total,
                display_total=display_total,
                entity_types=entity_types,
                etype_filter=etype,
                q_filter=q,
                table_filter=table_filter,
                has_alerts_filter=has_alerts,
                sort=sort,
                data_tables=data_table_names,
            ),
            headers={"Cache-Control": "no-cache"},
        )

    # --------------------------------------------------------------
    # Entity detail
    # --------------------------------------------------------------
    @r.get("/entities/{entity_id:path}", response_class=HTMLResponse)
    async def entity_detail(request: Request, entity_id: str):
        entity = None
        related_alerts: list[dict] = []
        related_entities: list[dict] = []
        recent_events: list[dict] = []
        tables: list[str] = []
        verdict_history: list[dict] = []

        try:
            entity = db.query_one("SELECT * FROM entities WHERE entity_id=?", [entity_id])
            if entity:
                entity = dict(entity)
                # Tables from side table (fast path) with live fallback
                tbl_rows = db.query(
                    "SELECT table_name FROM entity_tables WHERE entity_id=?",
                    [entity_id],
                )
                tables = sorted({r["table_name"] for r in tbl_rows})
                if not tables:
                    combos = _relevant_columns(entity.get("type", ""))
                    for table, col in combos:
                        try:
                            row = db.query_one(
                                f'SELECT 1 AS found FROM "{table}" WHERE "{col}" = ? LIMIT 1',
                                [entity["value"]],
                            )
                            if row:
                                tables.append(table)
                        except Exception:
                            logger.debug("entity_detail: ignored error", exc_info=True)
                    tables = sorted(set(tables))

                # Related alerts via JSON entities column (single scan, then filter)
                try:
                    alert_rows = db.query(
                        "SELECT alert_id, title, severity, status, entities, created_at FROM alerts WHERE entities IS NOT NULL ORDER BY created_at DESC LIMIT 50",
                    )
                    for a in alert_rows:
                        ents = a.get("entities")
                        if isinstance(ents, str):
                            try:
                                ents = json.loads(ents)
                            except Exception:
                                ents = []
                        if isinstance(ents, list):
                            for ent in ents:
                                if f"{ent.get('type')}:{ent.get('value','').lower()}" == entity_id:
                                    related_alerts.append(dict(a))
                                    break
                except Exception:
                    logger.debug("entity_detail: ignored error", exc_info=True)

                # Graph edges
                related_entities = db.query(
                    "SELECT e.*, ed.relation, ed.weight FROM entity_edges ed JOIN entities e ON (e.entity_id=ed.dst_entity) WHERE ed.src_entity=? ORDER BY ed.weight DESC LIMIT 20",
                    [entity_id],
                )
                import math

                for i, e in enumerate(related_entities[:8]):
                    angle = (i / max(len(related_entities), 1)) * 2 * math.pi
                    e["_gx"] = int(250 + 130 * math.cos(angle))
                    e["_gy"] = int(100 + 70 * math.sin(angle))

                # Recent events via KQL
                if _has(_KQL) and entity.get("type") == "ip":
                    try:
                        result = _KQL.run_kql(
                            db,
                            f'search * | where SrcIp == "{entity["value"]}" or DstIp == "{entity["value"]}" | take 20',
                            origin="ui",
                            log=False,
                        )
                        recent_events = [dict(zip(result.columns, row)) for row in result.rows]
                    except Exception:
                        logger.debug("entity_detail: ignored error", exc_info=True)

                # Verdict history from alerts
                try:
                    vh_rows = db.query(
                        "SELECT alert_id, verdict, verdict_by, updated_at FROM alerts WHERE entities IS NOT NULL ORDER BY updated_at DESC LIMIT 100"
                    )
                    for vr in vh_rows:
                        ents = vr.get("entities")
                        if isinstance(ents, str):
                            try:
                                ents = json.loads(ents)
                            except Exception:
                                ents = []
                        if isinstance(ents, list):
                            for ent in ents:
                                if f"{ent.get('type')}:{ent.get('value','').lower()}" == entity_id:
                                    if vr.get("verdict"):
                                        verdict_history.append(dict(vr))
                                    break
                except Exception:
                    logger.debug("entity_detail: ignored error", exc_info=True)
        except Exception:
            logger.debug("entity_detail: ignored error", exc_info=True)

        if not entity:
            return HTMLResponse("<div class='empty-state'>Entity not found.</div>", status_code=404)

        entity["_tables"] = sorted(tables)
        entity["_reltime"] = _reltime(entity.get("last_seen"))

        return templates.TemplateResponse(
            request,
            "entity_detail.html",
            _ctx(
                request,
                "entities",
                f"Entity: {entity.get('value', '')}",
                entity=entity,
                related_alerts=related_alerts,
                related_entities=related_entities,
                recent_events=recent_events,
                verdict_history=verdict_history,
            ),
            headers={"Cache-Control": "no-cache"},
        )

    # --------------------------------------------------------------
    # API: watch toggle
    # --------------------------------------------------------------
    @r.put("/api/entities/{entity_id:path}/watch")
    async def api_entity_watch(entity_id: str):
        try:
            e = db.query_one("SELECT watch FROM entities WHERE entity_id=?", [entity_id])
            if not e:
                return JSONResponse({"error": "Not found"}, status_code=404)
            new_val = not e["watch"]
            db.execute("UPDATE entities SET watch = ? WHERE entity_id=?", [new_val, entity_id])
            audit_record(db, "user:web", "entity.watch.toggle", "entity", entity_id, outcome="ok", details={"watch": new_val})
            return {"ok": True, "watch": new_val}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    # --------------------------------------------------------------
    # API: notes
    # --------------------------------------------------------------
    @r.post("/api/entities/{entity_id:path}/notes")
    async def api_entity_notes(entity_id: str, request: Request):
        try:
            body = await request.json()
            notes = body.get("notes", "")
            db.execute("UPDATE entities SET notes=? WHERE entity_id=?", [notes, entity_id])
            audit_record(db, "user:web", "entity.notes.update", "entity", entity_id, outcome="ok")
            return {"ok": True}
        except Exception as exc:
            return JSONResponse({"error": str(exc)}, status_code=500)

    return r
