"""Agents page routes: card grid, detail, run history, recommendations, policy editor.

Mounted BEFORE legacy routes.py so /agents and /agents/{name} override.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..audit import record as audit_record
from ..db import Database, new_id, utcnow

# Import helpers from routes.py (same template env)
from ._rec_apply import SPECIAL_KINDS, apply_rule_tune, apply_special_kind
from .routes import _ctx, _severity_choices, templates  # type:ignore[attr-defined]

logger = logging.getLogger(__name__)

# Feature-detect agent modules
_AGENTS_BASE = _AGENTS_REG = None
try:
    from siempl.agents.base import MODES, SEVERITY_ORDER, Agent, resolve_policy  # type:ignore[import-untyped]  # noqa: F401
    _AGENTS_BASE = True
    try:
        from siempl.agents.registry import list_agents
        _AGENTS_REG = sorted(
            list_agents())  # type: ignore[assignment]
    except (ImportError, AttributeError):
        _AGENTS_REG = []
except ImportError:
    _AGENTS_BASE = False

# Agent card metadata: name -> description, icon hint
AGENT_CARDS: dict[str, dict[str, Any]] = {
    "onboarding": {
        "title": "Source Onboarding",
        "description": "Auto-detects or proposes parsers for new log sources by examining raw samples. Uses heuristics first; optional LLM enrichment.",
        "icon": "📥",
    },
    "optimizer": {
        "title": "Ingestion Optimization",
        "description": "Analyzes table usage vs alert rules to recommend ingest filters and retention changes that reduce cost.",
        "icon": "⚡",
    },
    "discovery": {
        "title": "Alert Rule Discovery",
        "description": "Three modes: validate data flow / import web rules (Sigma/Sentinel) / scan streams and create baseline alerts.",
        "icon": "🔍",
    },
    "tuning": {
        "title": "Rule Tuning",
        "description": "Recurring agent that monitors alert frequency, FP/TP ratios, and proposes threshold or query adjustments.",
        "icon": "🎚️",
    },
    "log_alert": {
        "title": "Log Alert",
        "description": "Optional cheap-LLM per-line scan of log tables for suspicious patterns. OFF by default.",
        "icon": "📝",
    },
    "triage": {
        "title": "Alert Triage",
        "description": "Investigates alerts with evidence-first analysis. Closes or escalates per policy. Can create temporary monitoring rules.",
        "icon": "🩺",
    },
    "remediation": {
        "title": "Remediation",
        "description": "Stub connectors (block IP, disable user, isolate host). Always dry-run; real connectors must be registered explicitly.",
        "icon": "🔒",
    },
}


def _has(module) -> bool:
    return module is not None


def _agent_status(db: Database, name: str) -> dict:
    """Return status fields for an agent card."""
    enabled = False
    last_run = None
    next_scheduled = None
    total_cost = 0.0

    # Per-agent enable flags
    if name == "log_alert":
        enabled = bool(db.get_setting("log_alert_agent_enabled", False))
    elif name == "remediation":
        enabled = bool(db.get_setting("remediation_enabled", False))
    else:
        # All other agents run when scheduler is on + dry_run not blocking them entirely
        enabled = bool(db.get_setting("agent_schedule_enabled", False))

    # Most recent run
    row = db.query_one(
        "SELECT started_at, finished_at, status, cost_usd FROM agent_runs WHERE agent=? ORDER BY started_at DESC LIMIT 1",
        [name])
    if row:
        last_run = dict(row)
        if isinstance(last_run.get("started_at"), datetime):
            last_run["started_at"] = last_run["started_at"].isoformat()
        if isinstance(last_run.get("finished_at"), datetime):
            last_run["finished_at"] = last_run["finished_at"].isoformat()
        total_cost = float(last_run.get("cost_usd") or 0.0)

    # Global schedule isn't per-agent, but we can compute next from interval settings if recurring
    if name in ("tuning", "optimizer", "triage"):
        interval_key = f"agent_{name}_interval_minutes"
        mins = int(db.get_setting(interval_key, 360 if name == "tuning" else 1440 if name == "optimizer" else 5))
        if mins > 0:
            next_scheduled = f"every {mins} min"

    return {
        "enabled": enabled,
        "last_run": last_run,
        "next_scheduled": next_scheduled,
        "total_cost": total_cost,
    }


def _policy_rows(db: Database) -> list[dict]:
    try:
        return db.query("SELECT * FROM agent_policy ORDER BY agent, scope DESC, scope_value")
    except Exception:
        return []


def _effective_policy(db: Database, agent: str, severity: str | None = None, rule_id: str | None = None) -> dict:
    """Compute effective resolved policy for display."""
    if not _AGENTS_BASE:
        return {"mode": "recommend", "source": "default"}
    p = resolve_policy(db, agent, severity=severity, rule_id=rule_id)
    src = "resolved"
    if severity:
        src = f"resolved (severity={severity})"
    elif rule_id:
        src = f"resolved (rule={rule_id})"
    else:
        src = "resolved (global)"
    return {
        "mode": p.mode,
        "can_close": p.can_close,
        "can_escalate": p.can_escalate,
        "can_remediate": p.can_remediate,
        "can_create_temp_rules": p.can_create_temp_rules,
        "source": src,
    }


def _recommendations_for_agent(db: Database, agent_name: str) -> list[dict]:
    try:
        return db.query("""
            SELECT * FROM recommendations
            WHERE agent=? AND status='open' ORDER BY created_at DESC LIMIT 100
        """, [agent_name])
    except Exception:
        return []


def _run_history_for_agent(db: Database, agent_name: str) -> list[dict]:
    try:
        rows = db.query(
            "SELECT * FROM agent_runs WHERE agent=? ORDER BY started_at DESC LIMIT 100",
            [agent_name])
        for r in rows:
            if isinstance(r.get("started_at"), datetime):
                r["started_at"] = r["started_at"].isoformat()  # type:ignore[dict-item]
            if isinstance(r.get("finished_at"), datetime):
                r["finished_at"] = r["finished_at"].isoformat()  # type:ignore[dict-item]
        return rows  # type:ignore[return-value]
    except Exception:
        return []


# ---- recommendation kind helpers -------------------------------------------

def _apply_recommendation(db: Database, rec_id: str, by: str = "user:web") -> dict:
    """Apply a single recommendation. Returns {"ok": bool, "message": str}."""
    try:
        rec = db.query_one("SELECT * FROM recommendations WHERE rec_id=?", [rec_id])
        if not rec:
            return {"ok": False, "message": "Recommendation not found"}
        if rec["status"] != "open":
            return {"ok": False, "message": f"Already {rec['status']}"}

        payload = json.loads(rec["payload"]) if isinstance(rec["payload"], str) else (rec["payload"] or {})
        kind = rec["kind"]
        target = rec["target"]

        if kind == "ingest_filter":
            fid = new_id("flt_")
            db.execute(
                "INSERT INTO ingest_filters(filter_id,table_name,expression,description,enabled,origin) VALUES (?,?,?,?,?,?)",
                [fid, target, payload.get("expression", ""), rec["title"], True, "recommendation"])

        elif kind == "retention":
            db.execute(
                "INSERT OR REPLACE INTO table_retention(table_name,retention_days) VALUES (?,?)",
                [target, payload.get("retention_days", 30)])

        elif kind == "rule_tune":
            q = payload.get("query")
            if q:
                apply_rule_tune(db, target, q, rec["rationale"])

        elif kind == "rule_disable":
            db.execute("UPDATE rules SET enabled=FALSE, updated_at=? WHERE rule_id=?", [utcnow(), target])

        elif kind == "rule_import":
            # Already imported but disabled; enable it
            db.execute("UPDATE rules SET enabled=TRUE, updated_at=? WHERE rule_id=?", [utcnow(), target])

        elif kind == "new_rule":
            from ..detect.engine import RuleStore
            rid = payload.get("rule_id") or new_id("rule_")
            if not db.query_one("SELECT 1 AS x FROM rules WHERE rule_id=? OR name=?", [rid, payload.get("name", rec["title"])]):
                RuleStore(db).create({**payload, "rule_id": rid, "name": payload.get("name", rec["title"]),
                                      "enabled": bool(payload.get("enabled", False)),
                                      "origin": payload.get("origin", "ai_generated")})

        elif kind in SPECIAL_KINDS:
            apply_special_kind(db, kind, target, payload, rec["rationale"])  # raises ValueError if it cannot apply

        else:
            return {"ok": False, "message": f"Unknown recommendation kind: {kind}"}

        db.execute(
            "UPDATE recommendations SET status='approved', decided_at=?, decided_by=? WHERE rec_id=?",
            [utcnow(), by, rec_id])
        return {"ok": True, "message": f"Applied {kind} on {target}"}
    except Exception as e:
        return {"ok": False, "message": f"Error: {e}"}


def _reject_recommendation(db: Database, rec_id: str, by: str = "user:web") -> dict:
    try:
        db.execute(
            "UPDATE recommendations SET status='rejected', decided_at=?, decided_by=? WHERE rec_id=?",
            [utcnow(), by, rec_id])
        return {"ok": True, "message": "Recommendation rejected"}
    except Exception as e:
        return {"ok": False, "message": str(e)}


# ---- router ----------------------------------------------------------------

def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/agents", response_class=HTMLResponse)
    async def agents_page(request: Request):
        agent_names = sorted(_AGENTS_REG) if _AGENTS_REG else []
        cards = []
        for ag in agent_names:
            meta = AGENT_CARDS.get(ag, {"title": ag, "description": "", "icon": "🤖"})
            status = _agent_status(db, ag)
            cards.append({**meta, "name": ag, **status})

        # run history for all
        runs: list[dict] = []
        recs: list[dict] = []
        try:
            runs = db.query("SELECT * FROM agent_runs ORDER BY started_at DESC LIMIT 100")
            for row in runs:
                if isinstance(row.get("started_at"), datetime):
                    row["started_at"] = row["started_at"].isoformat()  # type:ignore[dict-item]
                if isinstance(row.get("finished_at"), datetime):
                    row["finished_at"] = row["finished_at"].isoformat()  # type:ignore[dict-item]
        except Exception:
            logger.debug("agents_page: ignored error", exc_info=True)

        try:
            recs = db.query("SELECT * FROM recommendations WHERE status='open' ORDER BY created_at DESC LIMIT 100")
        except Exception:
            logger.debug("agents_page: ignored error", exc_info=True)

        # Open alerts for triage picker
        open_alerts: list[dict] = []
        try:
            open_alerts = db.query("SELECT alert_id, title, severity, status, created_at FROM alerts WHERE status='new' ORDER BY created_at DESC LIMIT 100")
        except Exception:
            logger.debug("agents_page: ignored error", exc_info=True)

        # AI panel data
        key_status = "not found"
        import os as _os
        if _os.environ.get("OPENROUTER_API_KEY"):
            key_status = "found"
        else:
            kf = db.get_setting("openrouter_key_file", "")
            if kf:
                from pathlib import Path
                if Path(kf).expanduser().is_file():
                    key_status = "found"

        usage_today = {"usd": 0.0, "tokens": 0}
        try:
            from ..ai.llm import LLMClient
            usage_today = LLMClient(db).usage_today()
        except Exception:
            logger.debug("agents_page: ignored error", exc_info=True)

        return templates.TemplateResponse(request, "agents.html", _ctx(
            request, "agents", "Agents",
            cards=cards,
            runs=runs,
            recs=recs,
            agents_dry_run=db.get_setting("agents_dry_run", True),
            ai_enabled=db.get_setting("ai_enabled", False),
            ai_daily_usd_cap=db.get_setting("ai_daily_usd_cap", 1.0),
            ai_total_usd_budget=db.get_setting("ai_total_usd_budget", 10.0),
            ai_cheap_model=db.get_setting("ai_cheap_model", "google/gemini-3.8-flash"),
            key_status=key_status,
            usage_today=usage_today,
            modes=MODES if _AGENTS_BASE else ["off", "monitor", "recommend", "auto_close", "auto_remediate"],
            severity_choices=_severity_choices(db),
            policy_rows=_policy_rows(db),
            open_alerts=open_alerts,
        ), headers={"Cache-Control": "no-cache"})

    @r.get("/agents/{agent_name}", response_class=HTMLResponse)
    async def agent_detail(request: Request, agent_name: str):
        if _AGENTS_REG and agent_name not in _AGENTS_REG:
            return HTMLResponse("<div class='empty-state'>Agent not found.</div>", status_code=404)
        meta = AGENT_CARDS.get(agent_name, {"title": agent_name, "description": "", "icon": "🤖"})
        status = _agent_status(db, agent_name)
        runs = _run_history_for_agent(db, agent_name)
        recs = _recommendations_for_agent(db, agent_name)
        policy = _policy_rows(db)

        # Per-agent model override
        model_override = db.get_setting(f"agent_model_{agent_name}", "")
        all_models = list(dict.fromkeys([
            db.get_setting("ai_default_model", ""),
            db.get_setting("ai_cheap_model", ""),
            "google/gemini-3.8-flash",
            "deepseek/deepseek-v4-pro",
            "anthropic/claude-sonnet-4",
            "openai/gpt-4.1-mini",
        ]))
        all_models = [m for m in all_models if m]

        # Effective policy sample for display
        eff_pol = _effective_policy(db, agent_name)

        return templates.TemplateResponse(request, "agent_detail.html", _ctx(
            request, "agents", f"Agent: {meta['title']}",
            agent_name=agent_name,
            meta=meta,
            **status,
            runs=runs,
            recs=recs,
            policy_rows=policy,
            effective_policy=eff_pol,
            agents_dry_run=db.get_setting("agents_dry_run", True),
            modes=MODES if _AGENTS_BASE else ["off", "monitor", "recommend", "auto_close", "auto_remediate"],
            severity_choices=_severity_choices(db),
            model_override=model_override,
            all_models=all_models,
        ), headers={"Cache-Control": "no-cache"})

    # ---- API endpoints ----------------------------------------------------

    @r.post("/api/agents/{agent_name}/run")
    async def api_agent_run(agent_name: str, request: Request):
        if not _AGENTS_BASE or (not _AGENTS_REG) or agent_name not in _AGENTS_REG:
            return JSONResponse({"error": f"Agent '{agent_name}' not available"}, status_code=503)
        try:
            body = await request.json()
        except Exception:
            body = {}
        if body is None:
            body = {}
        try:
            from ..agents.registry import run_agent
            dry_run = db.get_setting("agents_dry_run", True)

            # Per-agent parameter dispatch
            kw: dict[str, Any] = {"dry_run": dry_run}
            if agent_name == "triage":
                alert_id = body.get("alert_id", "").strip()
                if alert_id:
                    kw["alert_id"] = alert_id
                else:
                    # triage_new_alerts path
                    limit = max(1, min(int(body.get("limit", 5)), 20))
                    from ..agents.triage import triage_new_alerts
                    results = triage_new_alerts(db, limit=limit)
                    # Summarise
                    statuses = [r.status for r in results]
                    total_cost = sum(r.cost for r in results)
                    return {
                        "ok": True,
                        "status": "ok",
                        "summary": f"Triage batch: {len(results)} alerts, statuses={set(statuses) or {'skipped'}}",
                        "results": [{"status": r.status, "summary": r.summary, "run_id": r.output.get("run_id", "")} for r in results],
                        "cost_usd": round(total_cost, 6),
                    }
            elif agent_name == "onboarding":
                sid = body.get("source_id", "").strip()
                if sid:
                    kw["source_id"] = sid
                samples = body.get("samples")
                if isinstance(samples, list):
                    kw["samples"] = samples
            elif agent_name == "optimizer":
                kw["window_days"] = max(1, min(int(body.get("window_days", 7)), 90))
            elif agent_name == "discovery":
                mode = body.get("mode", "validate_sources")
                kw["mode"] = mode
                if mode == "import_web":
                    from ..detect.importer import _default_client
                    kw["http_client"] = _default_client()   # real GitHub fetch (cached on disk)
            elif agent_name == "tuning":
                rid = body.get("rule_ids", [])
                if isinstance(rid, str) and rid:
                    kw["rule_ids"] = [rid]
                elif isinstance(rid, list):
                    kw["rule_ids"] = rid
                kw["window_days"] = max(1, min(int(body.get("window_days", 30)), 90))
            elif agent_name == "log_alert":
                kw["table"] = str(body.get("table", "Syslog")).strip() or "Syslog"
                kw["limit"] = max(1, min(int(body.get("limit", 50)), 200))

            result = run_agent(db, agent_name, **kw)
            audit_record(db, "user:web", "agent.run", "agent", agent_name,
                         outcome="ok" if not dry_run else "dry_run",
                         details={"status": result.status, "summary": result.summary[:200]})
            return {"ok": True, "run_id": result.output.get("run_id", ""),
                    "status": result.status, "summary": result.summary}
        except Exception as e:
            audit_record(db, "user:web", "agent.run", "agent", agent_name,
                         outcome="error", details={"error": str(e)[:200]})
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/agents/{agent_name}/toggle")
    async def api_agent_toggle(agent_name: str):
        """Toggle agent-specific enable flags."""
        try:
            if agent_name == "log_alert":
                key = "log_alert_agent_enabled"
            elif agent_name == "remediation":
                key = "remediation_enabled"
            else:
                # global schedule
                key = "agent_schedule_enabled"
            current = bool(db.get_setting(key, False))
            db.set_setting(key, not current)
            audit_record(db, "user:web", "agent.toggle", "setting", key,
                         outcome="ok", details={"enabled": not current, "agent": agent_name})
            return {"ok": True, "enabled": not current}
        except Exception as e:
            audit_record(db, "user:web", "agent.toggle", "setting", agent_name,
                         outcome="error", details={"error": str(e)[:200]})
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/agents/{agent_name}/schedule")
    async def api_agent_schedule(agent_name: str, request: Request):
        """Update per-agent schedule interval (minutes)."""
        try:
            body = await request.json()
            mins = int(body.get("interval_minutes", 0))
            key = f"agent_{agent_name}_interval_minutes"
            db.set_setting(key, max(0, mins))
            audit_record(db, "user:web", "agent.schedule", "setting", key,
                         outcome="ok", details={"agent": agent_name, "interval_minutes": max(0, mins)})
            return {"ok": True, "interval_minutes": max(0, mins)}
        except Exception as e:
            audit_record(db, "user:web", "agent.schedule", "setting", agent_name,
                         outcome="error", details={"error": str(e)[:200]})
            return JSONResponse({"error": str(e)}, status_code=500)

    @r.post("/api/recommendations/{rec_id}/apply")
    async def api_rec_apply(rec_id: str):
        result = _apply_recommendation(db, rec_id, by="user:web")
        audit_record(db, "user:web", "recommendation.apply", "recommendation", rec_id,
                     outcome="ok" if result["ok"] else "error", details={"message": result["message"][:200]})
        if result["ok"]:
            return {"ok": True, "message": result["message"]}
        return JSONResponse({"error": result["message"]}, status_code=400)

    @r.post("/api/recommendations/{rec_id}/reject")
    async def api_rec_reject(rec_id: str):
        result = _reject_recommendation(db, rec_id, by="user:web")
        audit_record(db, "user:web", "recommendation.reject", "recommendation", rec_id,
                     outcome="ok" if result["ok"] else "error", details={"message": result["message"][:200]})
        if result["ok"]:
            return {"ok": True, "message": result["message"]}
        return JSONResponse({"error": result["message"]}, status_code=400)

    @r.post("/api/settings/policy")
    async def api_policy_update(request: Request):
        if not _AGENTS_BASE:
            return JSONResponse({"error": "agents module not available"}, status_code=503)
        try:
            body = await request.json()
            agent = body.get("agent", "triage")
            scope = body.get("scope", "global")
            scope_value = body.get("scope_value", "*")
            mode = body.get("mode", "recommend")
            if mode not in (MODES if _AGENTS_BASE else ["off", "monitor", "recommend", "auto_close", "auto_remediate"]):
                return JSONResponse({"error": f"Invalid mode: {mode}"}, status_code=400)
            db.execute(
                "INSERT OR REPLACE INTO agent_policy(agent,scope,scope_value,mode,can_close,can_escalate,can_remediate,can_create_temp_rules) VALUES (?,?,?,?,?,?,?,?)",
                [agent, scope, scope_value, mode,
                 bool(body.get("can_close", True)),
                 bool(body.get("can_escalate", True)),
                 bool(body.get("can_remediate", False)),
                 bool(body.get("can_create_temp_rules", True))])
            audit_record(db, "user:web", "policy.update", "policy", f"{agent}:{scope}:{scope_value}",
                         outcome="ok", details={"mode": mode})
            return {"ok": True}
        except Exception as e:
            audit_record(db, "user:web", "policy.update", "policy", agent,
                         outcome="error", details={"error": str(e)[:200]})
            return JSONResponse({"error": str(e)}, status_code=500)

    return r
