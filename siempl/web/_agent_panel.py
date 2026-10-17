"""Agent panel helpers: scope -> agent mapping, policy gate, pending recs, attention.

Pure data logic on top of agents.base / agents.registry and routes_agents helpers.
The HTTP layer lives in routes_agent_panel.py. Nothing here edits other modules.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta
from typing import Any

from ..agents._safety import findings_for_output, scan_many
from ..agents.base import Policy, resolve_policy
from ..db import Database, utcnow
from .routes_agents import _agent_status

SCOPES = ("alert", "rule", "source", "logs")
SCOPE_AGENT = {"alert": "triage", "rule": "tuning", "source": "onboarding", "logs": "log_alert"}
SCOPE_REC_AGENTS = {
    "alert": ("triage",),
    "rule": ("tuning", "discovery"),
    "source": ("onboarding", "optimizer"),
    "logs": ("log_alert",),
}
# Policy capability each recommendation kind needs before a human may apply it.
# None = human-only decision, never policy-gated (injection_review).
KIND_CAPABILITY: dict[str, str | None] = {
    "ingest_filter": "can_remediate",
    "retention": "can_remediate",
    "rule_tune": "can_remediate",
    "rule_disable": "can_remediate",
    "entity_exclusion": "can_remediate",
    "onboard_source": "can_remediate",
    "rule_import": "can_create_temp_rules",
    "new_rule": "can_create_temp_rules",
    "injection_review": None,
}
RULE_KINDS = ("rule_tune", "rule_disable", "rule_import", "entity_exclusion")
AGENT_PORTAL = {"triage": "alerts", "tuning": "rules", "discovery": "rules",
                "optimizer": "ingestion", "onboarding": "ingestion", "log_alert": "logs"}
KIND_PORTAL = {"rule_tune": "rules", "rule_disable": "rules", "rule_import": "rules", "new_rule": "rules", "entity_exclusion": "rules",
               "ingest_filter": "ingestion", "retention": "ingestion", "onboard_source": "ingestion"}
WAITING_RUN_STATUSES = ("waiting_approval", "awaiting_approval")
ATTENTION_LIMIT = 50
PENDING_LIMIT = 200
OUTPUT_CAP = 2000
RUN_STALE_MINUTES = 30   # a 'running' row older than this no longer blocks new runs

_INFLIGHT: set[tuple[str, str]] = set()
_INFLIGHT_LOCK = threading.Lock()


def claim(agent: str, key: str) -> bool:
    """Mark (agent, key) as running in this process. False if already claimed."""
    with _INFLIGHT_LOCK:
        if (agent, key) in _INFLIGHT:
            return False
        _INFLIGHT.add((agent, key))
        return True


def release(agent: str, key: str) -> None:
    with _INFLIGHT_LOCK:
        _INFLIGHT.discard((agent, key))


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def _loads(value: Any) -> Any:
    if value is None:
        return {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return {}
    return value


def _trim_output(raw: Any) -> str | None:
    if raw is None:
        return None
    text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    return text if len(text) <= OUTPUT_CAP else text[:OUTPUT_CAP] + "...[trimmed]"


def policy_dict(p: Policy) -> dict:
    return {"mode": p.mode, "can_close": p.can_close, "can_escalate": p.can_escalate,
            "can_remediate": p.can_remediate, "can_create_temp_rules": p.can_create_temp_rules}


def scope_context(db: Database, scope: str, target_id: str) -> dict | None:
    """Resolve a panel target. None when the target does not exist (-> 404)."""
    agent = SCOPE_AGENT[scope]
    ctx: dict[str, Any] = {"scope": scope, "target_id": target_id, "agent": agent,
                           "key": target_id, "severity": None, "rule_id": None, "targets": [], "texts": []}
    if scope == "logs":
        ctx.update(key="logs", targets=None)
    elif scope == "alert":
        row = db.query_one("SELECT * FROM alerts WHERE alert_id=?", [target_id])
        if not row:
            return None
        ctx.update(severity=row["severity"], rule_id=row["rule_id"], targets=[target_id],
                   texts=[row["title"], row["description"], row["evidence"]])
    elif scope == "rule":
        row = db.query_one("SELECT * FROM rules WHERE rule_id=?", [target_id])
        if not row:
            return None
        ctx.update(severity=row["severity"], rule_id=target_id, targets=[target_id],
                   texts=[row["name"], row["description"], row["query"]])
    else:
        row = db.query_one("SELECT * FROM sources WHERE source_id=?", [target_id])
        if not row:
            return None
        ctx.update(targets=[target_id, row["target_table"]], texts=[row["name"], row["notes"]])
    ctx["policy"] = resolve_policy(db, agent, severity=ctx["severity"], rule_id=ctx["rule_id"])
    ctx["enabled"] = bool(_agent_status(db, agent)["enabled"])
    ctx["running"] = is_running(db, agent, ctx["key"])
    return ctx


def is_running(db: Database, agent: str, key: str) -> bool:
    with _INFLIGHT_LOCK:
        if (agent, key) in _INFLIGHT:
            return True
    since = utcnow() - timedelta(minutes=RUN_STALE_MINUTES)
    row = db.query_one(
        "SELECT 1 AS x FROM agent_runs WHERE agent=? AND input_ref=? AND status='running' AND started_at>=? LIMIT 1",
        [agent, key, since])
    return row is not None


def run_block_reason(ctx: dict) -> str | None:
    """Reason a run may not start (disabled agent or policy off). None = allowed."""
    if not ctx["enabled"]:
        return f"agent '{ctx['agent']}' is disabled"
    if ctx["policy"].mode == "off":
        return f"policy mode is off for agent '{ctx['agent']}'"
    return None


def run_kwargs(agent: str, key: str, dry_run: bool) -> dict[str, Any]:
    """Keyword arguments for run_agent() for a panel target (mirrors routes_agents dispatch)."""
    kw: dict[str, Any] = {"dry_run": dry_run, "input_ref": key}
    if agent == "triage":
        kw["alert_id"] = key
    elif agent == "onboarding":
        kw["source_id"] = key
    elif agent == "tuning":
        kw["rule_ids"] = [key]
        kw["window_days"] = 30
    elif agent == "log_alert":
        kw["table"] = "Syslog"
        kw["limit"] = 50
    return kw


def run_background(db: Database, agent: str, key: str) -> None:
    """Background run for a panel target. Same run_agent path as routes_agents.api_agent_run."""
    from ..agents.registry import run_agent
    from ..audit import record as audit_record
    try:
        dry_run = bool(db.get_setting("agents_dry_run", True))
        result = run_agent(db, agent, **run_kwargs(agent, key, dry_run))
        audit_record(db, "user:web", "agent.run", "agent", agent, outcome="ok" if not dry_run else "dry_run",
                     details={"status": result.status, "target_id": key, "summary": result.summary[:200]})
    except Exception as e:  # noqa: BLE001
        audit_record(db, "user:web", "agent.run", "agent", agent, outcome="error",
                     details={"target_id": key, "error": str(e)[:200]})
    finally:
        release(agent, key)


def _rec_context(db: Database, rec: dict) -> tuple[str | None, str | None]:
    """(severity, rule_id) the recommendation's target is governed by."""
    if rec["kind"] in RULE_KINDS:
        row = db.query_one("SELECT severity FROM rules WHERE rule_id=?", [rec["target"]])
        return (row["severity"], rec["target"]) if row else (None, None)
    row = db.query_one("SELECT severity, rule_id FROM alerts WHERE alert_id=?", [rec["target"]])
    return (row["severity"], row["rule_id"]) if row else (None, None)


def block_reason(policy: Policy, agent: str, kind: str) -> str | None:
    """Policy-matrix gate for a human approval. None = allowed."""
    cap = KIND_CAPABILITY.get(kind, "can_remediate")
    if cap is None:
        return None  # injection_review: always human-approvable / dismissable
    if policy.mode == "off":
        return f"policy mode is off for agent '{agent}'"
    if not getattr(policy, cap):
        return f"policy for agent '{agent}' does not allow {cap}"
    return None


def rec_block_reason(db: Database, rec: dict) -> str | None:
    sev, rule_id = _rec_context(db, rec)
    pol = resolve_policy(db, rec["agent"], severity=sev, rule_id=rule_id)
    return block_reason(pol, rec["agent"], rec["kind"])


def _rec_matches(rec: dict, ctx: dict) -> bool:
    if ctx["targets"] is None:  # logs scope: every open log_alert recommendation
        return rec["agent"] == "log_alert"
    return rec["target"] in ctx["targets"]


def pending_recs(db: Database, scope: str, ctx: dict) -> list[dict]:
    agents = SCOPE_REC_AGENTS[scope]
    marks = ",".join("?" * len(agents))
    rows = db.query(
        f"SELECT * FROM recommendations WHERE status='open' AND (agent IN ({marks}) OR kind='injection_review') "
        "ORDER BY created_at DESC LIMIT ?", [*agents, PENDING_LIMIT])
    return [r for r in rows if _rec_matches(r, ctx)]


def pending_item(db: Database, rec: dict) -> dict:
    reason = rec_block_reason(db, rec)
    return {"id": rec["rec_id"], "kind": rec["kind"], "title": rec["title"], "rationale": rec["rationale"],
            "payload": _loads(rec["payload"]), "created_at": _iso(rec["created_at"]),
            "allowed": reason is None, "blocked_reason": reason}


def last_run(db: Database, agent: str, key: str) -> dict | None:
    row = db.query_one(
        "SELECT run_id, status, started_at, finished_at, summary, output, error, cost_usd FROM agent_runs "
        "WHERE agent=? AND input_ref=? ORDER BY started_at DESC LIMIT 1", [agent, key])
    if not row:
        return None
    return {"run_id": row["run_id"], "status": row["status"], "started_at": _iso(row["started_at"]),
            "finished_at": _iso(row["finished_at"]), "summary": row["summary"],
            "output": _trim_output(row["output"]), "error": row["error"],
            "cost_usd": float(row["cost_usd"] or 0.0)}


def injection_info(ctx: dict) -> dict:
    findings = findings_for_output(scan_many(*ctx["texts"])) if ctx["texts"] else []
    return {"detected": bool(findings), "findings": findings}


def panel_state(db: Database, ctx: dict) -> dict:
    """Shape of GET /api/agent-panel/{scope}/{target_id}."""
    run_reason = "agent is running for this target" if ctx["running"] else run_block_reason(ctx)
    return {
        "scope": ctx["scope"], "target_id": ctx["target_id"], "agent": ctx["agent"],
        "enabled": ctx["enabled"], "ai_enabled": bool(db.get_setting("ai_enabled", False)),
        "policy": policy_dict(ctx["policy"]),
        "last_run": last_run(db, ctx["agent"], ctx["key"]),
        "running": ctx["running"],
        "pending": [pending_item(db, r) for r in pending_recs(db, ctx["scope"], ctx)],
        "injection": injection_info(ctx),
        "actions": {"can_run": run_reason is None, "run_blocked_reason": run_reason},
    }


def portal_for(agent: str, kind: str) -> str:
    if kind == "injection_review":
        return "alerts"
    return AGENT_PORTAL.get(agent) or KIND_PORTAL.get(kind, "alerts")


def _attention_item(db: Database, portal: str, row: dict, is_run: bool) -> dict:
    """One attention entry. Keys portal/kind/id/title are the original contract; the rest are additive."""
    if is_run:
        return {"portal": portal, "kind": "waiting_approval", "id": row["run_id"],
                "title": row["summary"] or f"{row['agent']} run", "rec_id": None, "target": row["input_ref"],
                "rationale": None, "allowed": False,
                "blocked_reason": "agent run is waiting for approval; open its page"}
    reason = rec_block_reason(db, row)
    return {"portal": portal, "kind": row["kind"], "id": row["rec_id"], "title": row["title"],
            "rec_id": row["rec_id"], "target": row["target"], "rationale": row["rationale"],
            "allowed": reason is None, "blocked_reason": reason}


def attention_summary(db: Database, limit: int = ATTENTION_LIMIT) -> dict:
    """Pending agent tasks needing a human. NOT new alerts, NOT failed runs."""
    recs = db.query("SELECT rec_id, agent, kind, target, title, rationale FROM recommendations "
                    "WHERE status='open' ORDER BY created_at DESC")
    marks = ",".join("?" * len(WAITING_RUN_STATUSES))
    runs = db.query(f"SELECT run_id, agent, summary, input_ref FROM agent_runs WHERE status IN ({marks}) "
                    "ORDER BY started_at DESC", list(WAITING_RUN_STATUSES))
    pending = [(portal_for(r["agent"], r["kind"]), False, r) for r in recs]
    pending += [(portal_for(r["agent"], "run"), True, r) for r in runs]
    by_portal = {"alerts": 0, "rules": 0, "ingestion": 0, "logs": 0}
    for portal, _is_run, _row in pending:
        by_portal[portal] += 1
    total = len(pending)
    items = [_attention_item(db, portal, row, is_run) for portal, is_run, row in pending[:limit]]
    return {"total": total, "by_portal": {**by_portal, "agents": total}, "items": items}
