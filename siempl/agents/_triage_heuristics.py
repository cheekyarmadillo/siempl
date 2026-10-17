"""Deterministic heuristic verdicts for TriageAgent when AI is disabled or over budget.

Signals (all read-only): rule history (closed_fp/closed_tp, 30d), repetition (same rule with
the same title or entity set, 24h), entity reputation, related OPEN alerts from other rules
sharing an entity (24h, kill-chain signal), and severity. Output shape matches the triage
verdict dict; recommended_actions are ACTION_ALLOWLIST names only, never free text.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from ..db import Database
from .base import SEVERITY_ORDER

FP_RATIO_MIN = 0.8        # rule closed_fp / closed >= 0.8 (integer-compared, see _rule_noisy)
FP_MIN_CLOSED = 5         # need at least this many closed alerts for the ratio rule
REPEAT_MIN = 5            # other same-rule repeats in 24h
RELATED_MIN = 2           # other open alerts from other rules sharing an entity
HIGH_REP = 80             # entity reputation strictly above this is hostile
BENIGN_REP = 20           # entity reputation at or below this is benign-leaning
HISTORY_DAYS = 30
REPEAT_WINDOW = timedelta(hours=24)
REPEAT_CAP = 500          # rows scanned for repetition, bounds the query


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _severity_idx(alert: dict) -> int:
    sev = (alert.get("severity") or "medium").lower()
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 3


def _alert_entities(alert: dict) -> list[tuple[str, str]]:
    """(type, value) pairs from the alert's entities JSON (string or list)."""
    raw = alert.get("entities")
    items = json.loads(raw) if isinstance(raw, str) and raw else (raw or [])
    if not isinstance(items, list):
        return []
    return [(str(e.get("type", "?")), e["value"]) for e in items
            if isinstance(e, dict) and isinstance(e.get("value"), str) and e.get("value")]


def _entity_set(alert: dict) -> frozenset:
    return frozenset(_alert_entities(alert))

def _rule_history(db: Database, rule_id: str | None) -> tuple[int, int]:
    """(closed_fp, closed_tp) counts for this rule over the history window."""
    if not rule_id:
        return 0, 0
    row = db.query_one(
        """SELECT COUNT(*) FILTER (WHERE status='closed_fp') AS fp,
                  COUNT(*) FILTER (WHERE status='closed_tp') AS tp
           FROM alerts WHERE rule_id=? AND status IN ('closed_fp','closed_tp')
           AND updated_at>=?""",
        [rule_id, _now() - timedelta(days=HISTORY_DAYS)])
    return int(row["fp"] or 0), int(row["tp"] or 0)


def _repeat_count(db: Database, alert: dict, rule_id: str | None) -> int:
    """Other alerts from the same rule in 24h with the same title or the same entity set."""
    if not rule_id:
        return 0
    rows = db.query(
        """SELECT alert_id, title, entities FROM alerts
           WHERE rule_id=? AND alert_id<>? AND created_at>=? LIMIT ?""",
        [rule_id, alert["alert_id"], _now() - REPEAT_WINDOW, REPEAT_CAP])
    key = _entity_set(alert)
    title = alert.get("title")
    return sum(1 for r in rows
               if (title and r.get("title") == title)
               or (key and _entity_set(r) == key))

def _related_open_count(db: Database, alert: dict, rule_id: str | None) -> int:
    """Distinct OPEN alerts from OTHER rules created in 24h that share an entity with this one."""
    values = {value for _, value in _alert_entities(alert)}
    if not values:
        return 0
    # Quoted JSON form avoids substring hits (10.0.0.1 inside 10.0.0.12).
    needles = [json.dumps(v).lower() for v in sorted(values)]
    clause = " OR ".join("instr(lower(CAST(entities AS VARCHAR)), ?) > 0" for _ in needles)
    rows = db.query(
        f"""SELECT alert_id FROM alerts
            WHERE status IN ('new','active') AND alert_id<>? AND COALESCE(rule_id,'')<>?
            AND created_at>=? AND ({clause})""",
        [alert["alert_id"], rule_id or "", _now() - REPEAT_WINDOW, *needles])
    return len({r["alert_id"] for r in rows})


def _reputation(entities: list[dict]) -> tuple[float, float, int, int]:
    """(max_rep, min_rep, fp_count, tp_count) over the context entity records."""
    max_rep = max((e.get("reputation", 50) for e in entities), default=50)
    min_rep = min((e.get("reputation", 50) for e in entities), default=50)
    fp = sum(e.get("fp_count", 0) or 0 for e in entities)
    tp = sum(e.get("tp_count", 0) or 0 for e in entities)
    return max_rep, min_rep, fp, tp

def _rule_noisy(s: dict) -> str | None:
    """Why this rule's alerts look like noise, or None."""
    closed = s["closed_fp"] + s["closed_tp"]
    # closed_fp / closed >= 0.8, written as integers to avoid float rounding at the boundary.
    if closed >= FP_MIN_CLOSED and s["closed_fp"] * 5 >= closed * 4:
        return f"rule FP ratio {s['closed_fp']}/{closed}"
    if s["repeats"] >= REPEAT_MIN and s["closed_tp"] == 0:
        return f"{s['repeats']} repeats in 24h, no TP history"
    return None


def _low_severity_fp(s: dict) -> tuple[str, float, str] | None:
    """False positive for low/informational alerts: benign-style entity rule, then rule history."""
    if s["sev_idx"] > 1:
        return None
    if s["max_rep"] <= BENIGN_REP and s["fp"] > 0:
        return "false_positive", 0.85, "low rep, low severity, FP history"
    if (why := _rule_noisy(s)):
        # Closed-alert history is real analyst evidence (0.90, can auto-close under policy). Repetition
        # alone is only a hint (0.80, below the 0.85 close threshold), so a human confirms the close.
        return "false_positive", (0.90 if why.startswith("rule FP ratio") else 0.80), why
    return None


def _decide(s: dict) -> tuple[str, float, str]:
    """Pure decision over the collected signals -> (verdict, confidence, reason)."""
    fp = _low_severity_fp(s)
    if fp:
        return fp
    if s["sev_idx"] >= 3 and (s["related"] >= RELATED_MIN or s["max_rep"] > HIGH_REP):
        return "true_positive", 0.75, f"{s['related']} related open alerts, max_rep={s['max_rep']}"
    if s["max_rep"] > HIGH_REP or s["sev_idx"] >= 4:
        return "needs_human", 0.80, "high rep or critical severity"
    return "needs_human", 0.50, "ambiguous: requires human analysis"

_ACTIONS = {
    "false_positive": ["close_alert", "tune_rule"],
    "true_positive": ["escalate_alert", "collect_more_evidence"],
    "needs_human_high": ["escalate_alert", "review_manually"],
    "needs_human": ["collect_more_evidence", "review_manually"],
}


def heuristic_verdict(db: Database, alert: dict, rule: dict | None,
                      entities: list[dict]) -> dict[str, Any]:
    """Rules-based pre-triage verdict (AI disabled). Same return shape as _heuristic_triage."""
    rule_id = alert.get("rule_id") or (rule or {}).get("rule_id")
    max_rep, min_rep, fp, tp = _reputation(entities)
    closed_fp, closed_tp = _rule_history(db, rule_id)
    s = {"sev_idx": _severity_idx(alert), "max_rep": max_rep, "fp": fp,
         "closed_fp": closed_fp, "closed_tp": closed_tp,
         "repeats": _repeat_count(db, alert, rule_id),
         "related": _related_open_count(db, alert, rule_id)}
    verdict, conf, reason = _decide(s)
    severity = (alert.get("severity") or "medium").lower()
    summary = (f"Deterministic heuristic: max_rep={max_rep}, min_rep={min_rep}, "
               f"severity={severity}(idx={s['sev_idx']}), fp_count={fp}, tp_count={tp}, "
               f"rule_closed_fp={closed_fp}, rule_closed_tp={closed_tp}, "
               f"repeats_24h={s['repeats']}, related_open_24h={s['related']}")
    monitor: list[dict] = []
    if verdict == "false_positive":
        actions = _ACTIONS["false_positive"]
    elif verdict == "true_positive":
        actions = _ACTIONS["true_positive"]
    elif conf == 0.80:
        actions = _ACTIONS["needs_human_high"]
        monitor = [{"type": t, "value": v} for t, v in _alert_entities(alert)[:5]]
    else:
        actions = _ACTIONS["needs_human"]
    return {
        "verdict": verdict,
        "confidence": conf,
        "severity_adjustment": None,
        "summary": f"{summary} -> {verdict} ({reason})",
        "evidence_refs": [f"entity:{e.get('entity_id', '?')}" for e in entities],
        "recommended_actions": list(actions),
        "monitor_entities": monitor,
        "monitor_patterns": [],
        "source": "heuristic",
    }
