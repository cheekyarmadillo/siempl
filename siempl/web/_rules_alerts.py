"""Rules x alerts: per-rule alert counts for the rules list, the 'Alerts from this rule' panel on the
rule detail page, and the 'Rule: <name>' chip on /alerts?rule=<id>.

Not for: rule CRUD and pages (routes_rules.py), the alerts list itself (routes_alerts_page.py) or
SVG drawing (_svg_charts.py).
"""
from __future__ import annotations

from urllib.parse import urlencode

from markupsafe import Markup

from ..alerts_status import STATUSES
from ..db import Database
from ._svg_charts import bar_svg

PANEL_ALERTS = 25  # latest alerts shown in the detail panel
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


def rule_alert_counts(db: Database) -> dict[str, dict]:
    """{rule_id: {'total', 'open'}} for every rule with alerts. One grouped query, however many alerts there are."""
    rows = db.query(
        "SELECT rule_id, count(*) AS total, "
        "count(*) FILTER (WHERE status IN ('new', 'active')) AS open_count "
        "FROM alerts WHERE rule_id IS NOT NULL GROUP BY rule_id")
    return {row["rule_id"]: {"total": int(row["total"]), "open": int(row["open_count"])} for row in rows}


def rules_with_alert_counts(db: Database, where: str, params: list) -> list[dict]:
    """Rules matching the list filters, each with alert_total and alert_open (new + active).

    `where` is built by the caller from fixed clauses; every value stays a bound parameter.
    """
    counts = rule_alert_counts(db)
    rules = db.query(f"SELECT * FROM rules WHERE {where} ORDER BY name LIMIT 500", params)
    out = []
    for rule in rules:
        count = counts.get(rule["rule_id"], {})
        out.append({**rule, "alert_total": count.get("total", 0), "alert_open": count.get("open", 0)})
    return out


def _alerts_href(rule_id: str, status: str | None = None) -> str:
    """/alerts filtered to one rule, optionally to one status (status=all shows every status)."""
    params = {"rule": rule_id, "status": status} if status else {"rule": rule_id}
    return "/alerts?" + urlencode(params)


def rule_alerts_panel(db: Database, rule_id: str) -> dict:
    """Data for the 'Alerts from this rule' panel: counts by status (bar chart, bars link to filtered
    lists), the latest PANEL_ALERTS alerts and the 'View all' link."""
    by_status = {row["status"]: int(row["c"]) for row in db.query(
        "SELECT status, count(*) AS c FROM alerts WHERE rule_id=? GROUP BY status", [rule_id])}
    bars = [(STATUS_LABELS[s], by_status.get(s, 0), STATUS_COLORS[s], _alerts_href(rule_id, s))
            for s in STATUSES]
    alerts = db.query(
        "SELECT alert_id, alert_number, severity, title, status, created_at FROM alerts WHERE rule_id=? "
        "ORDER BY created_at DESC NULLS LAST LIMIT ?", [rule_id, PANEL_ALERTS])
    return {
        "total": sum(by_status.values()),
        "svg": Markup(bar_svg(bars, width=340)),
        "alerts": alerts,
        "view_all": f"/alerts?{urlencode({'rule': rule_id, 'status': 'all'})}",
    }


def rule_chip(db: Database, rule_id: str) -> dict | None:
    """Chip data for /alerts?rule=<id>: the rule's name, or the bare id when the rule no longer exists."""
    if not rule_id:
        return None
    row = db.query_one("SELECT name FROM rules WHERE rule_id=?", [rule_id])
    return {"name": row["name"] if row else rule_id}


