"""Full alert page: GET /alerts/{alert_id}. One alert with its evidence, entities, MITRE, rule, comments and history.

Mounted before routes.py, which no longer serves this path. The page only reads; every change is a
JSON call made by alert_detail.js (routes_alerts_api.py), so audit and derived fields stay in one place.
Not for: the alert list (routes_alerts_page.py) or the status rules (alerts_status.py).
"""
from __future__ import annotations

import json
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from ..alerts_status import SEVERITIES, STATUSES
from ..db import Database
from .routes import _ctx, templates
from .routes_alerts_api import _json_list

EVIDENCE_LIMIT = 200
HISTORY_LIMIT = 100
STATUS_LABELS = {
    "new": "New",
    "active": "Active",
    "closed_tp": "Closed - True Positive",
    "closed_fp": "Closed - False Positive",
}
HISTORY_ACTIONS = {"alert.status": "Status", "alert.severity": "Severity", "alert.owner": "Owner"}
STATUS_CHOICES = [(s, STATUS_LABELS[s]) for s in STATUSES]
SEVERITY_CHOICES = [(s, s.capitalize()) for s in SEVERITIES]


def entity_cards(raw) -> list[dict]:
    """Entities as {label, href}; href points at the entity page. Non-object items are skipped."""
    cards = []
    for ent in _json_list(raw):
        if not isinstance(ent, dict) or not ent.get("type") or ent.get("value") is None:
            continue
        entity_id = f"{ent['type']}:{str(ent['value']).lower()}"
        cards.append({"label": f"{ent['type']}:{ent['value']}", "href": "/entities/" + quote(entity_id, safe="")})
    return cards


def evidence_table(raw) -> dict:
    """Evidence rows as {columns, rows}: columns are the union of row keys in first-seen order."""
    rows = [row for row in _json_list(raw) if isinstance(row, dict)][:EVIDENCE_LIMIT]
    columns = list(dict.fromkeys(key for row in rows for key in row))
    return {"columns": columns, "rows": [[row.get(c) for c in columns] for row in rows], "total": len(rows)}


def _details(raw) -> dict:
    """The details object inside an audit row's RawEvent JSON; {} when absent or unreadable."""
    try:
        event = json.loads(raw) if isinstance(raw, str) else {}
    except json.JSONDecodeError:
        return {}
    details = event.get("details") if isinstance(event, dict) else None
    return details if isinstance(details, dict) else {}


def audit_history(db: Database, alert_id: str) -> list[dict]:
    """Status, severity and owner changes to this alert, newest first, with from and to values."""
    actions = list(HISTORY_ACTIONS)
    marks = ",".join("?" for _ in actions)
    rows = db.query(
        "SELECT TimeGenerated, Actor, Action, RawEvent FROM SiemplAudit "
        f"WHERE TargetId = ? AND Action IN ({marks}) ORDER BY TimeGenerated DESC LIMIT ?",
        [alert_id, *actions, HISTORY_LIMIT])
    history = []
    for row in rows:
        details = _details(row.get("RawEvent"))
        history.append({
            "when": str(row.get("TimeGenerated") or "")[:19],
            "actor": row.get("Actor") or "",
            "field": HISTORY_ACTIONS.get(row.get("Action") or "", row.get("Action")),
            "before": details.get("from"),
            "after": details.get("to"),
        })
    return history


def alert_detail_data(db: Database, alert_id: str) -> dict | None:
    """Everything the full alert page shows, or None when the alert does not exist."""
    row = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_id])
    if row is None:
        return None
    alert = dict(row)
    rule = db.query_one("SELECT rule_id, name, description, mitre_tactics FROM rules WHERE rule_id=?",
                        [alert.get("rule_id")])
    return {
        "alert": alert,
        "rule": rule,
        "evidence": evidence_table(alert.get("evidence")),
        "entities": entity_cards(alert.get("entities")),
        "mitre_techniques": list(alert.get("mitre_techniques") or []),
        "mitre_tactics": list((rule or {}).get("mitre_tactics") or []),
        "comments": db.query(
            "SELECT comment_id, author, body, ts FROM alert_comments WHERE alert_id=? ORDER BY ts", [alert_id]),
        "history": audit_history(db, alert_id),
    }


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/alerts/{alert_id}", response_class=HTMLResponse)
    async def alert_detail(request: Request, alert_id: str):
        data = alert_detail_data(db, alert_id)
        if data is None:
            return HTMLResponse("<div class='empty-state'>Alert not found.</div>", status_code=404)
        number = data["alert"].get("alert_number")
        title = f"Alert #{number}" if number else "Alert"
        status_label = STATUS_LABELS.get(data["alert"].get("status") or "", data["alert"].get("status"))
        ctx = _ctx(request, "alerts", title, status_choices=STATUS_CHOICES, severity_choices=SEVERITY_CHOICES,
                   status_label=status_label, **data)
        return templates.TemplateResponse(request, "alert_detail.html", ctx, headers={"Cache-Control": "no-cache"})

    return r
