"""Alert pages: the list (charts, filters, pagination, bulk actions), the chart fragment and the full alert page.

Mounted before routes.py (any routes_*.py is). The pages use alerts.js, which calls the JSON API in
routes_alerts_api.py for every write, so audit and derived fields stay in one place.
Not for: the JSON API (routes_alerts_api.py), the status rules (alerts_status.py) or SVG drawing (_svg_charts.py).
"""
from __future__ import annotations

import json
import math
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from markupsafe import Markup

from ..alerts_status import SEVERITIES, STATUSES
from ..db import Database
from ._rules_alerts import rule_chip
from ._svg_charts import SEVERITY_COLORS, bar_svg, legend_items, pie_svg
from .routes import _ctx, templates
from .routes_alerts_api import _json_list, summary_data

PAGE_SIZE = 50
DEFAULT_STATUS = "open"  # open = new + active
FILTER_STATUSES = ("open", "all", *STATUSES)
SEVERITY_LABELS = {sev: sev.capitalize() for sev in SEVERITIES}
STATUS_LABELS = {
    "new": "New",
    "active": "Active",
    "closed_tp": "Closed - True Positive",
    "closed_fp": "Closed - False Positive",
}
STATUS_COLORS = {
    "new": "var(--color-orange)",
    "active": "var(--color-accent)",
    "closed_tp": "var(--color-green)",
    "closed_fp": "var(--color-muted)",
}
SORT_COLUMNS = {"number": "a.alert_number", "created": "a.created_at"}
AUDIT_ACTIONS = {"alert.status": "Status", "alert.severity": "Severity", "alert.owner": "Owner"}
_URL_DEFAULTS = {"status": DEFAULT_STATUS, "sort": "number", "dir": "desc", "page": 1}
_STATUS_OPTIONS = [(s, STATUS_LABELS[s]) for s in STATUSES]
_LIST_STATUS_OPTIONS = [("open", "Open (new + active)"), ("all", "All"), *_STATUS_OPTIONS]
_SEVERITY_OPTIONS = [(s, SEVERITY_LABELS[s]) for s in SEVERITIES]


def _url(**params) -> str:
    """/alerts with only the non-default parameters, so the bare list is plain /alerts."""
    kept = {k: v for k, v in params.items() if v not in (None, "") and v != _URL_DEFAULTS.get(k)}
    return "/alerts" + (f"?{urlencode(kept)}" if kept else "")


def parse_filters(severity: str, status: str, q: str, sort: str, direction: str, rule: str = "") -> dict:
    """Normalise list-page parameters. Unknown values fall back to the defaults rather than failing."""
    return {
        "status": status if status in FILTER_STATUSES else DEFAULT_STATUS,
        "severity": severity if severity in SEVERITIES else "",
        "q": q.strip()[:200],
        "sort": sort if sort in SORT_COLUMNS else "number",
        "dir": direction if direction in ("asc", "desc") else "desc",
        "rule": rule.strip()[:200],
    }


def _where(f: dict) -> tuple[str, list]:
    """WHERE clause and its parameters for the list filters (values are always bound, never spliced)."""
    clauses: list[str] = []
    params: list = []
    if f["status"] == "open":
        clauses.append("a.status IN ('new', 'active')")
    elif f["status"] != "all":
        clauses.append("a.status = ?")
        params.append(f["status"])
    if f["severity"]:
        clauses.append("a.severity = ?")
        params.append(f["severity"])
    if f["q"]:
        clauses.append("instr(lower(a.title), lower(?)) > 0")
        params.append(f["q"])
    if f["rule"]:
        clauses.append("a.rule_id = ?")
        params.append(f["rule"])
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def _order(f: dict) -> str:
    direction = "ASC" if f["dir"] == "asc" else "DESC"
    return f"{SORT_COLUMNS[f['sort']]} {direction} NULLS LAST, a.created_at DESC"


def list_rows(db: Database, f: dict, requested_page: int) -> tuple[list[dict], int, int, int]:
    """One page of list rows. Returns (rows, total, page, pages); page is clamped to the last page."""
    where, params = _where(f)
    total = int(db.query_one(f"SELECT count(*) AS c FROM alerts a{where}", params)["c"])  # type:ignore[index]
    pages = max(1, math.ceil(total / PAGE_SIZE))
    page = min(max(requested_page, 1), pages)
    rows = db.query(
        "SELECT a.alert_id, a.alert_number, a.title, a.severity, a.status, a.created_at, "
        "r.name AS rule_name FROM alerts a LEFT JOIN rules r ON a.rule_id = r.rule_id"
        f"{where} ORDER BY {_order(f)} LIMIT ? OFFSET ?",
        [*params, PAGE_SIZE, (page - 1) * PAGE_SIZE])
    return rows, total, page, pages


def charts_context(db: Database, rule: str = "") -> dict:
    """Pie of open alerts by severity and bars of alerts by status, each slice/bar linking to a filtered list.

    With `rule` set, the counts (and the slice/bar links) are for that rule only, like the list below them.
    """
    summary = summary_data(db, rule)
    open_by_sev = summary["open_by_severity"]
    slices = [(sev, open_by_sev.get(sev, 0), SEVERITY_COLORS[sev]) for sev in SEVERITIES]
    hrefs = {sev: _url(severity=sev, rule=rule) for sev in SEVERITIES}
    legend = legend_items(slices)
    for item in legend:
        item["name"] = SEVERITY_LABELS[item["label"]]
        item["href"] = hrefs[item["label"]]
    bars = [(STATUS_LABELS[s], summary["by_status"].get(s, 0), STATUS_COLORS[s], _url(status=s, rule=rule))
            for s in STATUSES]
    return {
        "open_total": summary["open_total"],
        "pie_svg": Markup(pie_svg(slices, hrefs=hrefs)),
        "pie_legend": legend,
        "status_svg": Markup(bar_svg(bars, width=340)),
    }


def sort_heads(f: dict) -> dict[str, dict]:
    """Sortable column headers: the URL that sorts by the column (flipping direction if already sorted on it)."""
    heads: dict[str, dict] = {}
    for column in SORT_COLUMNS:
        active = f["sort"] == column
        flipped = "asc" if active and f["dir"] == "desc" else "desc"
        arrow = ("\u2191" if f["dir"] == "asc" else "\u2193") if active else ""
        heads[column] = {"url": _url(**{**f, "sort": column, "dir": flipped, "page": 1}), "arrow": arrow}
    return heads


def page_links(f: dict, page: int, pages: int) -> dict:
    """Previous and next URLs for the pager (None where there is no such page)."""
    return {
        "prev": _url(**{**f, "page": page - 1}) if page > 1 else None,
        "next": _url(**{**f, "page": page + 1}) if page < pages else None,
    }


def _audit_history(db: Database, alert_id: str) -> list[dict]:
    """Status, severity and owner changes made to this alert, newest first, with from/to values."""
    rows = db.query(
        "SELECT TimeGenerated, Actor, Action, RawEvent FROM SiemplAudit "
        "WHERE TargetId = ? AND Action IN ('alert.status', 'alert.severity', 'alert.owner') "
        "ORDER BY TimeGenerated DESC LIMIT 100", [alert_id])
    history = []
    for row in rows:
        details = _audit_details(row.get("RawEvent"))
        history.append({"when": row["TimeGenerated"], "actor": row["Actor"],
                        "field": AUDIT_ACTIONS.get(row["Action"], row["Action"]),
                        "from": details.get("from"), "to": details.get("to")})
    return history


def _audit_details(raw) -> dict:
    """The details object inside an audit row's RawEvent JSON; {} when absent or unreadable.

    Best-effort display data: a bad row shows as blank, it does not fail the page.
    """
    try:
        event = json.loads(raw) if isinstance(raw, str) else {}
    except json.JSONDecodeError:
        return {}
    details = event.get("details") if isinstance(event, dict) else None
    return details if isinstance(details, dict) else {}


def alert_detail_data(db: Database, alert_id: str) -> dict | None:
    """Everything the full alert page shows, or None when the alert does not exist."""
    alert = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_id])
    if alert is None:
        return None
    alert = dict(alert)
    return {
        "alert": alert,
        "rule": db.query_one("SELECT * FROM rules WHERE rule_id=?", [alert.get("rule_id")]),
        "evidence_rows": [row for row in _json_list(alert.get("evidence")) if isinstance(row, dict)],
        "entities": [ent for ent in _json_list(alert.get("entities")) if isinstance(ent, dict)],
        "comments": db.query(
            "SELECT comment_id, author, body, ts FROM alert_comments WHERE alert_id=? ORDER BY ts", [alert_id]),
        "history": _audit_history(db, alert_id),
    }


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/alerts", response_class=HTMLResponse)
    async def alerts_page(request: Request, severity: str = "", status: str = DEFAULT_STATUS, q: str = "",
                          sort: str = "number", direction: str = Query("desc", alias="dir"),
                          page: int = Query(1, ge=1), preview: str = "", rule: str = ""):
        f = parse_filters(severity, status, q, sort, direction, rule)
        rows, total, page_no, pages = list_rows(db, f, page)
        f_page = {**f, "page": page_no}
        ctx = _ctx(request, "alerts", "Alerts", rows=rows, total=total, current_page=page_no, pages=pages,
                   filters=f_page, status_choices=_LIST_STATUS_OPTIONS, severity_choices=_SEVERITY_OPTIONS,
                   sort_heads=sort_heads(f_page), pager=page_links(f_page, page_no, pages),
                   preview_id=preview, rule_chip=rule_chip(db, f["rule"]),
                   rule_clear_url=_url(**{**f_page, "rule": ""}), **charts_context(db, f["rule"]))
        return templates.TemplateResponse(request, "alerts.html", ctx, headers={"Cache-Control": "no-cache"})

    @r.get("/alerts/fragments/charts", response_class=HTMLResponse)
    async def alerts_charts_fragment(request: Request, rule: str = ""):
        ctx = {"request": request, **charts_context(db, rule.strip()[:200])}
        return templates.TemplateResponse(request, "alerts_charts.html", ctx, headers={"Cache-Control": "no-cache"})

    return r
