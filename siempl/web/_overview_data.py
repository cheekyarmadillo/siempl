"""Data for the overview page (/): plain dicts for KPI tiles and panels. No markup.

Two clocks. Event tables store UTC-naive TimeGenerated (see _ingestion_overview). Alerts, agent_runs and
ai_usage store DuckDB local-naive timestamps, so their windows are anchored on the database's own now().
Not for: chart markup (routes_overview.py) or page layout (templates/overview.html).
"""
from __future__ import annotations

from datetime import datetime

from ..db import Database
from ._ingestion_overview import (
    RANGES,
    _bucket_starts,
    _range_counts,
    _source_health,
    _table_totals,
    _totals_per_bucket,
    _utc_now,
    parse_range,
)

SEVERITIES = ("critical", "high", "medium", "low", "informational")
RECENT_RUNS = 8
TOP_N = 5
TOP_TABLES = 12
DEFAULT_BUDGET = 10.0


def _db_now(db: Database) -> datetime:
    """DuckDB's own current local time, naive: the clock alerts, agent runs and AI usage were stamped with."""
    return db.query_one("SELECT now()::TIMESTAMP AS n")["n"]


def _count(db: Database, sql: str, params: list | None = None) -> int:
    """Run a query whose single row has a column aliased c, and return it as int (0 when no row)."""
    row = db.query_one(sql, params or [])
    return int(row["c"] or 0) if row else 0


def _usd(db: Database, sql: str, params: list | None = None) -> float:
    """Run a query whose single row has a column aliased usd, and return it as float."""
    row = db.query_one(sql, params or [])
    return float(row["usd"] or 0.0) if row else 0.0

def _alert_kpis(db: Database, cutoff: datetime) -> dict:
    """Open alerts (status new or active, any age) and alerts created since *cutoff*."""
    return {
        "open": _count(db, "SELECT count(*) AS c FROM alerts WHERE status IN ('new', 'active')"),
        "opened": _count(db, "SELECT count(*) AS c FROM alerts WHERE created_at >= ?", [cutoff]),
    }


def _agent_kpis(db: Database, cutoff: datetime) -> dict:
    """Agent runs started since *cutoff*, and how many of them ended in status error."""
    row = db.query_one("SELECT count(*) AS runs, count(*) FILTER (WHERE status = 'error') AS failed "
                       "FROM agent_runs WHERE started_at >= ?", [cutoff])
    return {"runs": int(row["runs"]), "failed": int(row["failed"])}


def _ai_spend(db: Database) -> dict:
    """AI spend today (DuckDB local date, as ai/llm.py counts it) and lifetime, against the total budget."""
    today = _usd(db, "SELECT coalesce(sum(cost_usd), 0) AS usd FROM ai_usage "
                     "WHERE CAST(ts AS DATE) = CAST(now() AS DATE)")
    total = _usd(db, "SELECT coalesce(sum(cost_usd), 0) AS usd FROM ai_usage")
    budget = float(db.get_setting("ai_total_usd_budget", DEFAULT_BUDGET))
    used_pct = min(100.0, total / budget * 100) if budget > 0 else 100.0
    return {"today_usd": today, "total_usd": total, "budget_usd": budget, "used_pct": used_pct}


def _pending_approvals(db: Database) -> int:
    """Agent recommendations waiting for a human decision (status open)."""
    return _count(db, "SELECT count(*) AS c FROM recommendations WHERE status = 'open'")

def _events_series(starts: list[datetime], per_table: dict, spec: dict) -> dict:
    """Total events per bucket across all data tables, with labels formatted for the range."""
    return {"labels": [s.strftime(spec["fmt"]) for s in starts],
            "values": [float(v) for v in _totals_per_bucket(starts, per_table)]}


def _events_by_table(totals: dict[str, int]) -> list[dict]:
    """Busiest tables first (ties by name), tables with no events in the range left out."""
    ranked = sorted(((t, n) for t, n in totals.items() if n > 0), key=lambda item: (-item[1], item[0]))
    return [{"table": t, "count": n} for t, n in ranked[:TOP_TABLES]]


def _alert_buckets(db: Database, spec: dict, db_now: datetime) -> dict:
    """Alerts created per bucket, per severity: bucket labels and one count list per severity."""
    starts = _bucket_starts(db_now, spec)
    secs = int(spec["bucket"].total_seconds())
    rows = db.query(
        f"SELECT time_bucket(INTERVAL {secs} SECOND, created_at, TIMESTAMP '1970-01-01') AS b, "
        "severity, count(*) AS c FROM alerts WHERE created_at >= ? AND created_at <= ? GROUP BY b, severity",
        [starts[0], db_now])
    counts = {(r["b"], r["severity"]): int(r["c"]) for r in rows}
    series = {sev: [counts.get((s, sev), 0) for s in starts] for sev in SEVERITIES}
    return {"labels": [s.strftime(spec["fmt"]) for s in starts], "series": series}

def _open_by_severity(db: Database) -> dict[str, int]:
    """Open alerts (new or active) per severity, every severity present even when zero."""
    rows = db.query("SELECT severity, count(*) AS c FROM alerts WHERE status IN ('new', 'active') GROUP BY severity")
    counts = {r["severity"]: int(r["c"]) for r in rows}
    return {sev: counts.get(sev, 0) for sev in SEVERITIES}


def _top_rules(db: Database, cutoff: datetime) -> list[dict]:
    """Rules that produced the most alerts since *cutoff*. Alerts whose rule is gone show the rule id."""
    rows = db.query(
        "SELECT coalesce(r.name, a.rule_id, '(no rule)') AS name, a.rule_id AS rule_id, count(*) AS c "
        "FROM alerts a LEFT JOIN rules r ON r.rule_id = a.rule_id WHERE a.created_at >= ? "
        "GROUP BY 1, 2 ORDER BY c DESC, name LIMIT ?", [cutoff, TOP_N])
    return [{"name": r["name"], "rule_id": r["rule_id"], "count": int(r["c"])} for r in rows]


def _top_entities(db: Database) -> list[dict]:
    """Entities with the highest reputation (0 benign .. 100 malicious), most-alerted first on ties."""
    rows = db.query("SELECT entity_id, type, value, reputation, alert_count, watch FROM entities "
                    "ORDER BY reputation DESC, alert_count DESC, value LIMIT ?", [TOP_N])
    return [{"entity_id": r["entity_id"], "type": r["type"], "value": r["value"],
             "reputation": float(r["reputation"] or 0.0), "alert_count": int(r["alert_count"] or 0),
             "watch": bool(r["watch"])} for r in rows]

def _recent_runs(db: Database) -> list[dict]:
    """The most recent agent runs, newest first, with a display-ready start time."""
    rows = db.query("SELECT run_id, agent, status, started_at, summary FROM agent_runs "
                    "ORDER BY started_at DESC NULLS LAST LIMIT ?", [RECENT_RUNS])
    return [{"run_id": r["run_id"], "agent": r["agent"] or "", "status": r["status"] or "",
             "started": r["started_at"].strftime("%m-%d %H:%M") if r["started_at"] else "",
             "summary": r["summary"] or ""} for r in rows]


def _source_summary(db: Database, error_ids: frozenset, utc_now: datetime) -> dict:
    """Source counts: active, in error (collector reports a failure), stale, and totals by status."""
    active, errors, stale = _source_health(db, error_ids, utc_now)
    by_status = {r["status"]: int(r["c"]) for r in
                 db.query("SELECT status, count(*) AS c FROM sources GROUP BY status")}
    return {"active": active, "error": len(errors), "stale": len(stale),
            "total": sum(by_status.values()), "by_status": by_status}

def _tiles(total: int, alerts: dict, agents: dict, pending: int, ai: dict) -> list[dict]:
    """KPI tiles for the top strip: value, short detail line, and whether to highlight it as a warning."""
    return [
        {"label": "Events in range", "value": f"{total:,}", "detail": "all data tables", "warn": False},
        {"label": "Open alerts", "value": str(alerts["open"]), "detail": "status new or active",
         "warn": alerts["open"] > 0},
        {"label": "Alerts opened", "value": str(alerts["opened"]), "detail": "created in range", "warn": False},
        {"label": "Agent runs", "value": str(agents["runs"]), "detail": f"{agents['failed']} failed",
         "warn": agents["failed"] > 0},
        {"label": "Pending approvals", "value": str(pending), "detail": "recommendations open",
         "warn": pending > 0},
        {"label": "AI spend today", "value": f"${ai['today_usd']:.2f}",
         "detail": f"${ai['total_usd']:.2f} of ${ai['budget_usd']:.2f} total", "warn": ai["used_pct"] >= 80},
    ]


def build_overview(db: Database, raw_range: str | None, error_ids=frozenset()) -> dict:
    """Everything the overview page shows for one range. *error_ids* are source ids a collector reports failing."""
    key = parse_range(raw_range)
    spec = RANGES[key]
    utc_now = _utc_now()
    db_now = _db_now(db)
    cutoff = db_now - spec["window"]
    starts, per_table = _range_counts(db, spec, utc_now)
    totals = _table_totals(per_table)
    alerts = _alert_kpis(db, cutoff)
    agents = _agent_kpis(db, cutoff)
    ai = _ai_spend(db)
    pending = _pending_approvals(db)
    return {
        "range": key, "ranges": list(RANGES), "label": spec["label"], "bucket_label": spec["bucket_label"],
        "tiles": _tiles(sum(totals.values()), alerts, agents, pending, ai),
        "events": _events_series(starts, per_table, spec),
        "events_by_table": _events_by_table(totals),
        "open_by_severity": _open_by_severity(db),
        "alert_buckets": _alert_buckets(db, spec, db_now),
        "top_rules": _top_rules(db, cutoff),
        "top_entities": _top_entities(db),
        "recent_runs": _recent_runs(db),
        "sources": _source_summary(db, frozenset(error_ids), utc_now),
        "ai": ai,
        "pending": pending,
    }
