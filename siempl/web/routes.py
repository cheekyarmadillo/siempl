"""Web routes: pages and /api/* JSON endpoints.

Every route depends on `db` (Database) bound at router build time.
Feature-detected optional modules expose try: blocks at the top;
pages render "not available" when a required module is absent.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..db import Database, new_id

logger = logging.getLogger(__name__)

# ---- feature detection -------------------------------------------------
_KQL = _DETECT = _ENTITIES = _INGEST = _COLLECTORS = _AGENTS_BASE = None
_AGENT_CLASSES: dict[str, type] = {}

try:
    import siempl.kql as _KQL  # type:ignore[import-untyped]
except ImportError:
    pass

try:
    import siempl.detect as _DETECT  # type:ignore[import-untyped]
except ImportError:
    pass

try:
    import siempl.entities as _ENTITIES  # type:ignore[import-untyped]
except ImportError:
    pass

try:
    import siempl.ingest as _INGEST  # type:ignore[import-untyped]
except ImportError:
    pass

try:
    import siempl.collectors as _COLLECTORS  # type:ignore[import-untyped]
except ImportError:
    pass

try:
    from siempl.agents.base import MODES, SEVERITY_ORDER, Agent, resolve_policy  # type:ignore[import-untyped]  # noqa: F401
    _AGENTS_BASE = True

    # Discover agent classes
    try:
        from siempl.agents.registry import AGENTS  # type:ignore[import-untyped]
        _AGENT_CLASSES = dict(AGENTS)
    except (ImportError, AttributeError):
        pass
except ImportError:
    _AGENTS_BASE = False


# ---- helpers -----------------------------------------------------------

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "web" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SEVERITY_CLASS: dict[str, str] = {
    "informational": "sev-info",
    "low": "sev-low",
    "medium": "sev-medium",
    "high": "sev-high",
    "critical": "sev-critical",
}

def _has(module) -> bool: return module is not None

def _mod_state():
    return {
        "kql": _has(_KQL), "detect": _has(_DETECT), "entities": _has(_ENTITIES),
        "ingest": _has(_INGEST), "collectors": _has(_COLLECTORS), "agents": _AGENTS_BASE,
    }

def _ctx(request: Request, page: str, title: str, **extra):
    return {"request": request, "page": page, "title": title,
            "modules": _mod_state(), "severity_class": SEVERITY_CLASS, **extra}

# ---- router ------------------------------------------------------------

def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    # ==================================================================
    #  Pages  (server-rendered with HTMX)
    # ==================================================================

    @r.get("/entities/{entity_id}", response_class=HTMLResponse)
    async def entity_detail(request: Request, entity_id: str):
        entity = None
        related_alerts: list[dict] = []
        related_entities: list[dict] = []
        recent_events: list[dict] = []
        try:
            entity = db.query_one("SELECT * FROM entities WHERE entity_id=?", [entity_id])
            if entity:
                entity = dict(entity)
                # Related alerts: find alerts whose entities JSON contains this entity
                related_alerts = db.query(
                    "SELECT * FROM alerts WHERE entities LIKE ? ORDER BY created_at DESC LIMIT 50",
                    [f"%{entity['value']}%"])

                # Graph edges
                related_entities = db.query(
                    "SELECT e.*, ed.relation, ed.weight FROM entity_edges ed JOIN entities e ON (e.entity_id=ed.dst_entity) WHERE ed.src_entity=? ORDER BY ed.weight DESC LIMIT 20",
                    [entity_id])
                # Precompute graph positions
                import math
                for i, e in enumerate(related_entities[:8]):
                    angle = (i / max(len(related_entities), 1)) * 2 * math.pi
                    e["_gx"] = int(250 + 130 * math.cos(angle))
                    e["_gy"] = int(100 + 70 * math.sin(angle))

                # Recent events via KQL
                if _has(_KQL) and entity.get("type") == "ip":
                    try:
                        result = _KQL.run_kql(
                            db, f'search * | where SrcIp == "{entity["value"]}" or DstIp == "{entity["value"]}" | take 20',
                            origin="ui", log=False)
                        recent_events = [dict(zip(result.columns, row)) for row in result.rows]
                    except Exception:
                        logger.debug("entity_detail: ignored error", exc_info=True)
        except Exception:
            logger.debug("entity_detail: ignored error", exc_info=True)

        if not entity:
            return HTMLResponse("<div class='empty-state'>Entity not found.</div>", status_code=404)

        return templates.TemplateResponse(request, "entity_detail.html", _ctx(
            request, "entities", f"Entity: {entity.get('value','')}", entity=entity,
            related_alerts=related_alerts, related_entities=related_entities, recent_events=recent_events),
            headers={"Cache-Control": "no-cache"})

    # ==================================================================
    #  API endpoints
    # ==================================================================

    @r.post("/api/rules/{rule_id}/test-run")
    async def api_rule_test_run(rule_id: str):
        """Test-run a rule's query, return results + row count."""
        if not _has(_KQL):
            return JSONResponse({"error": "KQL module not available"}, status_code=503)
        try:
            rule = db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])
            if not rule:
                return JSONResponse({"error": "Rule not found"}, status_code=404)
            if (rule.get("query_lang") or "kql") == "sql":
                from ..detect._run_rule import run_rule_query
                result = run_rule_query(db, rule["query"], rule_id=rule_id, log=False, query_lang="sql",
                                        lookback_minutes=max(int(rule.get("lookback_minutes") or 5), 60 * 24 * 365))
            else:
                result = _KQL.run_kql(db, rule["query"], origin="user", log=False)
            return {"columns": result.columns, "rows": result.rows, "row_count": len(result.rows),
                    "truncated": result.truncated, "elapsed_ms": result.elapsed_ms}
        except _KQL.KqlError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.put("/api/rules/{rule_id}/toggle")
    async def api_rule_toggle(rule_id: str):
        try:
            r = db.query_one("SELECT enabled FROM rules WHERE rule_id=?", [rule_id])
            if not r:
                return JSONResponse({"error": "Not found"}, status_code=404)
            db.execute("UPDATE rules SET enabled = NOT enabled, updated_at = now() WHERE rule_id = ?", [rule_id])
            return {"ok": True, "enabled": not r["enabled"]}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/alerts/{alert_id}/comment")
    async def api_alert_comment(alert_id: str, request: Request):
        try:
            body = await request.json()
            body_text = body.get("body", "").strip()
            if not body_text:
                return JSONResponse({"error": "Empty comment"}, status_code=400)
            cid = new_id("cmt_")
            db.execute("INSERT INTO alert_comments(comment_id, alert_id, author, body) VALUES (?,?,?,?)",
                       [cid, alert_id, "web", body_text])
            return {"ok": True, "comment_id": cid}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.put("/api/entities/{entity_id}/watch")
    async def api_entity_watch(entity_id: str):
        try:
            e = db.query_one("SELECT watch FROM entities WHERE entity_id=?", [entity_id])
            if not e:
                return JSONResponse({"error": "Not found"}, status_code=404)
            db.execute("UPDATE entities SET watch = NOT watch WHERE entity_id=?", [entity_id])
            return {"ok": True, "watch": not e["watch"]}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/entities/{entity_id}/notes")
    async def api_entity_notes(entity_id: str, request: Request):
        try:
            body = await request.json()
            db.execute("UPDATE entities SET notes=? WHERE entity_id=?", [body.get("notes", ""), entity_id])
            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/recommendations/{rec_id}/{action}")
    async def api_recommendation_action(rec_id: str, action: str):
        """Approve or dismiss a recommendation."""
        if action not in ("approve", "dismiss"):
            return JSONResponse({"error": "Invalid action"}, status_code=400)
        try:
            rec = db.query_one("SELECT * FROM recommendations WHERE rec_id=?", [rec_id])
            if not rec:
                return JSONResponse({"error": "Not found"}, status_code=404)
            status = "approved" if action == "approve" else "dismissed"
            db.execute("UPDATE recommendations SET status=?, decided_at=now(), decided_by=? WHERE rec_id=?",
                       [status, "human:web", rec_id])

            # If approve and it's an ingest filter or retention recommendation, apply the payload
            if action == "approve":
                if rec["kind"] == "ingest_filter":
                    payload = json.loads(rec["payload"]) if isinstance(rec["payload"], str) else rec["payload"]
                    fid = new_id("flt_")
                    db.execute(
                        "INSERT INTO ingest_filters(filter_id,table_name,expression,description,enabled,origin) VALUES (?,?,?,?,?,?)",
                        [fid, rec["target"], payload.get("expression", ""), rec["title"], True, "recommendation"])
                elif rec["kind"] == "retention":
                    payload = json.loads(rec["payload"]) if isinstance(rec["payload"], str) else rec["payload"]
                    db.execute(
                        "INSERT OR REPLACE INTO table_retention(table_name,retention_days) VALUES (?,?)",
                        [rec["target"], payload.get("retention_days", 30)])

            return {"ok": True}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ---- Health -------------------------------------------------------

    @r.get("/health")
    async def health():
        return {"status": "ok", "modules": _mod_state()}

    return r


def _severity_choices(db: Database) -> list[tuple[str, str]]:
    try:
        rows = db.query("SELECT DISTINCT severity FROM rules WHERE severity IS NOT NULL ORDER BY severity")
        return [(r["severity"], r["severity"].capitalize()) for r in rows]
    except Exception:
        return [("informational","Info"), ("low","Low"), ("medium","Medium"), ("high","High"), ("critical","Critical")]
