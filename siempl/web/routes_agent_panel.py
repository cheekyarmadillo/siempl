"""Agent panel API: per-target agent state, background run, policy-gated approve/reject, attention.

Auto-mounted by siempl/web/__init__.py. Reuses routes_agents helpers (never edited here).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from ..audit import record as audit_record
from ..db import Database, utcnow
from ._agent_panel import (
    SCOPES,
    attention_summary,
    claim,
    panel_state,
    rec_block_reason,
    run_background,
    run_block_reason,
    scope_context,
)
from .routes_agents import _apply_recommendation, _reject_recommendation


async def _body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - empty or invalid body is treated as {}
        return {}
    return body if isinstance(body, dict) else {}


def _err(message: str, status: int, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": message, **extra}, status_code=status)


def _open_rec(db: Database, rec_id: str) -> tuple[dict | None, JSONResponse | None]:
    rec = db.query_one("SELECT * FROM recommendations WHERE rec_id=?", [rec_id])
    if not rec:
        return None, _err("recommendation not found", 404)
    if rec["status"] != "open":
        return None, _err(f"recommendation already {rec['status']}", 409)
    return rec, None


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/api/agent-panel/{scope}/{target_id}")
    async def get_panel(scope: str, target_id: str):
        if scope not in SCOPES:
            return _err(f"unknown scope '{scope}'", 404)
        ctx = scope_context(db, scope, target_id)
        if ctx is None:
            return _err(f"unknown {scope} '{target_id}'", 404)
        return panel_state(db, ctx)

    @r.post("/api/agent-panel/{scope}/{target_id}/run")
    async def post_panel_run(scope: str, target_id: str, background: BackgroundTasks):
        if scope not in SCOPES:
            return _err(f"unknown scope '{scope}'", 404)
        ctx = scope_context(db, scope, target_id)
        if ctx is None:
            return _err(f"unknown {scope} '{target_id}'", 404)
        if ctx["running"]:
            return _err("agent already running for this target", 409)
        reason = run_block_reason(ctx)
        if reason:
            return _err(reason, 400)
        if not claim(ctx["agent"], ctx["key"]):
            return _err("agent already running for this target", 409)
        background.add_task(run_background, db, ctx["agent"], ctx["key"])
        return {"ok": True, "status": "started", "agent": ctx["agent"], "target_id": target_id}

    @r.post("/api/agent-panel/recommendations/{rec_id}/approve")
    async def post_approve(rec_id: str):
        rec, err = _open_rec(db, rec_id)
        if err is not None or rec is None:
            return err
        reason = rec_block_reason(db, rec)
        if reason:
            audit_record(db, "user:web", "recommendation.apply", "recommendation", rec_id,
                         outcome="blocked", details={"blocked_reason": reason[:200]})
            return _err(reason, 403, blocked_reason=reason)
        if rec["kind"] == "injection_review":  # no apply step exists: acknowledge only
            db.execute("UPDATE recommendations SET status='approved', decided_at=?, decided_by=? WHERE rec_id=?",
                       [utcnow(), "user:web", rec_id])
            result = {"ok": True, "message": "Acknowledged injection_review (no side effects)"}
        else:
            result = _apply_recommendation(db, rec_id, by="user:web")
        audit_record(db, "user:web", "recommendation.apply", "recommendation", rec_id,
                     outcome="ok" if result["ok"] else "error", details={"message": result["message"][:200]})
        if result["ok"]:
            return {"ok": True, "rec_id": rec_id, "message": result["message"]}
        return _err(result["message"], 400)

    @r.post("/api/agent-panel/recommendations/{rec_id}/reject")
    async def post_reject(rec_id: str, request: Request):
        body = await _body(request)
        rec, err = _open_rec(db, rec_id)
        if err is not None:
            return err
        note = str(body.get("note") or "")[:500]
        result = _reject_recommendation(db, rec_id, by="user:web")
        audit_record(db, "user:web", "recommendation.reject", "recommendation", rec_id,
                     outcome="ok" if result["ok"] else "error",
                     details={"message": result["message"][:200], "note": note, "kind": rec["kind"]})
        if result["ok"]:
            return {"ok": True, "rec_id": rec_id, "message": result["message"]}
        return _err(result["message"], 400)

    @r.get("/api/agent-attention")
    async def get_attention():
        return attention_summary(db)

    return r
