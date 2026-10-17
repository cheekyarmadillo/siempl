"""Alert JSON API: status and severity writes, preview, summary, verdict compat shim, retired-route redirects.

Mounted before the legacy routes.py router (see web/__init__.py). Every write goes through
alerts_status.set_status / set_severity, so audit, derived verdict and reputation stay consistent.
Not for: the alert pages (routes.py) or the status rules themselves (alerts_status.py).
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from ..alerts_status import (
    OWNER_MAX_LENGTH,
    SEVERITIES,
    STATUSES,
    is_open,
    set_owner,
    set_severity,
    set_status,
)
from ..db import Database

ACTOR = "user:web"
PREVIEW_EVIDENCE_ROWS = 5
# Compat: the retired verdict API. benign folds into closed_fp; escalate reopens as active.
VERDICT_TO_STATUS: dict[str, str] = {
    "true_positive": "closed_tp",
    "false_positive": "closed_fp",
    "benign": "closed_fp",
    "escalate": "active",
}


def _error(message: str, code: int) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=code)


def _result(found: bool, **fields) -> JSONResponse:
    if not found:
        return _error("Alert not found", 404)
    return JSONResponse({"ok": True, **fields})


async def _body_dict(request: Request) -> dict | None:
    """The request body as a JSON object, or None when it is missing, malformed or not an object."""
    try:
        body = await request.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _json_list(value) -> list:
    """A JSON column (string or already-decoded list) as a list; anything else is []."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    return value if isinstance(value, list) else []


def owner_error(raw) -> str | None:
    """Why *raw* is not a valid owner value, or None. Owner is text up to OWNER_MAX_LENGTH, or null to clear."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        return "owner must be a string or null"
    if len(raw.strip()) > OWNER_MAX_LENGTH:
        return f"owner must be at most {OWNER_MAX_LENGTH} characters"
    return None


def preview_data(db: Database, alert_id: str) -> dict | None:
    """Everything the alert preview shows, or None when the alert does not exist."""
    alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_id])
    if alert is None:
        return None
    rule = db.query_one("SELECT rule_id, name, mitre_tactics FROM rules WHERE rule_id=?",
                        [alert.get("rule_id")])
    comments = db.query(
        "SELECT comment_id, author, body, ts FROM alert_comments WHERE alert_id=? ORDER BY ts", [alert_id])
    return {
        "alert_id": alert["alert_id"],
        "alert_number": alert.get("alert_number"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "description": alert.get("description"),
        "owner": alert.get("owner"),
        "created_at": alert.get("created_at"),
        "updated_at": alert.get("updated_at"),
        "window_start": alert.get("window_start"),
        "window_end": alert.get("window_end"),
        "row_count": alert.get("row_count"),
        "rule_id": alert.get("rule_id"),
        "rule_name": rule["name"] if rule else None,
        "entities": _json_list(alert.get("entities")),
        "evidence": _json_list(alert.get("evidence"))[:PREVIEW_EVIDENCE_ROWS],
        "comments": comments,
        "mitre": {
            "techniques": list(alert.get("mitre_techniques") or []),
            "tactics": list(rule["mitre_tactics"] or []) if rule else [],
        },
    }


def summary_data(db: Database, rule_id: str = "") -> dict:
    """Alert counts: open alerts by severity, all alerts by status, and the open total (optionally for one rule)."""
    by_status: dict[str, int] = dict.fromkeys(STATUSES, 0)
    open_by_severity: dict[str, int] = {}
    where, params = ("WHERE rule_id = ? ", [rule_id]) if rule_id else ("", [])
    for row in db.query(f"SELECT status, severity, count(*) AS c FROM alerts {where}GROUP BY status, severity", params):
        count = int(row["c"])
        status = row["status"] or "unknown"
        by_status[status] = by_status.get(status, 0) + count
        if is_open(row["status"]):
            severity = row["severity"] or "unknown"
            open_by_severity[severity] = open_by_severity.get(severity, 0) + count
    return {
        "open_by_severity": open_by_severity,
        "by_status": by_status,
        "open_total": sum(open_by_severity.values()),
    }


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.post("/api/alerts/{alert_id}/status")
    async def alert_set_status(alert_id: str, request: Request):
        body = await _body_dict(request)
        if body is None:
            return _error("JSON object body required", 400)
        status = body.get("status")
        if status not in STATUSES:
            return _error(f"Invalid status: {status}", 400)
        return _result(set_status(db, alert_id, status, ACTOR), status=status)

    @r.post("/api/alerts/{alert_id}/severity")
    async def alert_set_severity(alert_id: str, request: Request):
        body = await _body_dict(request)
        if body is None:
            return _error("JSON object body required", 400)
        severity = body.get("severity")
        if severity not in SEVERITIES:
            return _error(f"Invalid severity: {severity}", 400)
        return _result(set_severity(db, alert_id, severity, ACTOR), severity=severity)

    @r.post("/api/alerts/{alert_id}/owner")
    async def alert_set_owner(alert_id: str, request: Request):
        body = await _body_dict(request)
        if body is None or "owner" not in body:
            return _error("JSON object body with an owner key required", 400)
        error = owner_error(body["owner"])
        if error:
            return _error(error, 400)
        owner = (body["owner"] or "").strip() or None
        return _result(set_owner(db, alert_id, owner, ACTOR), owner=owner)

    @r.get("/api/alerts/summary")
    async def alert_summary(rule: str = ""):
        return summary_data(db, rule.strip()[:200])

    @r.get("/api/alerts/{alert_id}/preview")
    async def alert_preview(alert_id: str):
        data = preview_data(db, alert_id)
        if data is None:
            return _error("Alert not found", 404)
        return data

    @r.post("/api/alerts/{alert_id}/verdict")
    async def alert_verdict_compat(alert_id: str, request: Request):
        body = await _body_dict(request)
        if body is None:
            return _error("JSON object body required", 400)
        verdict = body.get("verdict")
        status = VERDICT_TO_STATUS.get(verdict) if isinstance(verdict, str) else None
        if status is None:
            return _error(f"Invalid verdict: {verdict}", 400)
        return _result(set_status(db, alert_id, status, ACTOR), status=status)

    @r.get("/incidents")
    async def incidents_retired():
        return RedirectResponse("/alerts", status_code=307)

    @r.get("/incidents/{incident_id}")
    async def incident_retired(incident_id: str):
        return RedirectResponse("/alerts", status_code=307)

    return r
