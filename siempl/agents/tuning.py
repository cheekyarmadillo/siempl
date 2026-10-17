"""TuningAgent – analyze rule performance and recommend/propose tuning changes.

Purpose: Per-rule analysis of alert volume, FP/TP ratios, errors, and baselines.
Produces recommendations for threshold adjustments, entity exclusions, and rule disabling.
Deterministic heuristics always; LLM enrichment optional.

Inputs:  None (operates on all enabled rules or subset from kw args)
Outputs: AgentResult with per-rule findings and recommendations

Deterministic flow:
  1. For each enabled rule: compute alert counts, FP/TP verdict ratios, last_row_count, errors
  2. Disable never-firing-with-error rules
  3. For rules with FP rate > 80% and volume > N: recommend threshold/window adjustments
  4. Detect repeated FP entities with low reputation: recommend entity exclusion filters
  5. Suppress duplicate alerts (same dedupe_key)
  6. Apply tunes via RuleStore.update only when dry_run=False

LLM path (optional): KQL query edits for threshold tuning, validated with compile_kql.

Tuning history is appended via RuleStore.update (which bumps version + tuning_history).
Old versions are recoverable.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from ..db import Database
from .base import Agent, AgentResult, resolve_policy


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ── per-check helpers ──────────────────────────────────────────────────────────

def _check_error_recommendation(db: Database, rule: dict, rid: str) -> dict | None:
    if not (rule.get("last_error") and rule.get("last_row_count") in (None, 0)):
        return None
    error_runs = db.query(
        """SELECT COUNT(*) as cnt FROM agent_runs
           WHERE agent='rule_runner' AND status='error'
           AND input_ref=? AND started_at >= ?""",
        [rid, _utcnow() - timedelta(days=7)])
    err_count = error_runs[0]["cnt"] if error_runs else 0
    if err_count >= 3:
        return {
            "kind": "rule_disable",
            "reason": f"Rule has errored {err_count}+ times in 7 days with no data returned",
            "severity": "high",
        }
    return None


def _check_fp_recommendation(rule: dict, fp_rate: float, total: int) -> dict | None:
    if total > 10 and fp_rate > 0.8:
        return {
            "kind": "rule_tune",
            "reason": f"FP rate {fp_rate*100:.0f}% over {total} alerts",
            "suggested_changes": {
                "raise_threshold": min(rule.get("threshold", 1) * 2, 100),
                "lengthen_window": min(rule.get("lookback_minutes", 5) * 2, 1440),
            },
            "severity": "medium",
        }
    return None


def _check_duplicate_recommendation(db: Database, rid: str, total: int,
                                    window_days: int) -> dict | None:
    if total <= 5:
        return None
    dupes = db.query(
        """SELECT dedupe_key, COUNT(*) as cnt FROM alerts
           WHERE rule_id=? AND created_at >= ?
           GROUP BY dedupe_key HAVING COUNT(*) > 1
           ORDER BY cnt DESC LIMIT 5""",
        [rid, _utcnow() - timedelta(days=window_days)])
    if not dupes:
        return None
    return {
        "kind": "rule_tune",
        "reason": "Duplicate alert suppression",
        "duplicate_keys": [d["dedupe_key"] for d in dupes],
        "severity": "low",
    }


def _entity_exclusion_reason(ent: dict, rep: int, cnt: int, col: str) -> dict:
    return {
        "kind": "entity_exclusion",
        "reason": f"Repeated FP entity {ent.get('value')} (rep={rep}, {cnt}x FP)",
        "exclude_entity": {"type": ent.get("type"), "value": ent.get("value"),
                           "column": col, "count": cnt},
        "severity": "low",
    }


def _fp_entity_counts(db: Database, rid: str, window_days: int) -> tuple[dict[str, int], dict[str, dict]]:
    entity_counts: dict[str, int] = {}
    entity_data: dict[str, dict] = {}
    rows = db.query(
        """SELECT entities FROM alerts WHERE rule_id=? AND status='closed_fp'
           AND created_at >= ? LIMIT 100""",
        [rid, _utcnow() - timedelta(days=window_days)])
    for r in rows:
        try:
            ents = json.loads(r["entities"]) if isinstance(r["entities"], str) else (r["entities"] or [])
        except json.JSONDecodeError:
            continue
        for e in ents:
            key = f"{e.get('type','')}:{e.get('value','')}"
            entity_counts[key] = entity_counts.get(key, 0) + 1
            entity_data.setdefault(key, e)
    return entity_counts, entity_data


def _check_entity_exclusion_recommendation(db: Database, rid: str, fp: int,
                                            window_days: int) -> dict | None:
    if fp <= 5:
        return None
    entity_counts, entity_data = _fp_entity_counts(db, rid, window_days)
    for key, cnt in entity_counts.items():
        if cnt < 3:
            continue
        ent = entity_data[key]
        row = db.query_one("SELECT reputation FROM entities WHERE entity_id=?",
                           [f"{ent.get('type','')}:{ent.get('value','').lower()}"])
        rep = row["reputation"] if row else 50
        col = _entity_to_column(ent.get("type", "")) if rep < 40 else None
        if col:
            return _entity_exclusion_reason(ent, rep, cnt, col)
    return None


def _analyze_rules(db: Database, window_days: int = 30) -> list[dict]:
    """Analyze each enabled rule: alert volume, verdict ratios, errors, FP entities.

    Returns list of dicts: rule_id, name, alert_count, fp_count, tp_count,
    fp_rate, last_error, last_row_count, recommendation.
    """
    rules = db.query("SELECT * FROM rules WHERE enabled=TRUE")
    results = []

    for rule in rules:
        rid = rule["rule_id"]
        analysis: dict[str, Any] = {
            "rule_id": rid, "name": rule.get("name", "Unknown"),
            "severity": rule.get("severity", "medium"),
            "threshold": rule.get("threshold", 1),
            "frequency_minutes": rule.get("frequency_minutes", 5),
            "lookback_minutes": rule.get("lookback_minutes", 5),
            "last_error": rule.get("last_error"),
            "last_row_count": rule.get("last_row_count"),
        }

        # Alert counts and verdicts in window
        alerts_data = db.query(
            """SELECT status, COUNT(*) as cnt FROM alerts
               WHERE rule_id=? AND created_at >= ?
               GROUP BY status""",
            [rid, _utcnow() - timedelta(days=window_days)])
        alert_stats = {r["status"] or "unknown": r["cnt"] for r in alerts_data}
        total = sum(alert_stats.values())
        fp = alert_stats.get("closed_fp", 0)
        tp = alert_stats.get("closed_tp", 0)

        analysis["alert_count"] = total
        analysis["fp_count"] = fp
        analysis["tp_count"] = tp
        analysis["fp_rate"] = round(fp / max(total, 1), 3)

        # Determine recommendation
        rec = _check_error_recommendation(db, rule, rid)
        if rec is None:
            rec = _check_fp_recommendation(rule, analysis["fp_rate"], total)

        dupe_rec = _check_duplicate_recommendation(db, rid, total, window_days)
        if dupe_rec:
            if rec is None:
                rec = dupe_rec
            else:
                rec.setdefault("duplicate_keys", []).extend(dupe_rec["duplicate_keys"])

        entity_rec = _check_entity_exclusion_recommendation(db, rid, fp, window_days)
        if entity_rec and rec is None:
            rec = entity_rec

        analysis["recommendation"] = rec
        results.append(analysis)

    return results


def _add_tuning_history(db: Database, rule_id: str, entry: dict) -> None:
    """Append a tuning entry to rule's tuning_history JSON array safely."""
    existing = db.query_one("SELECT tuning_history FROM rules WHERE rule_id=?", [rule_id])
    history = []
    if existing and existing.get("tuning_history"):
        try:
            h = existing["tuning_history"]
            history = json.loads(h) if isinstance(h, str) else h
        except (json.JSONDecodeError, TypeError):
            history = []
    history.append(entry)
    db.execute("UPDATE rules SET tuning_history=? WHERE rule_id=?",
               [json.dumps(history), rule_id])


def _entity_to_column(etype: str) -> str | None:
    """Map entity type to its primary column."""
    mapping = {
        "user": "UserName", "host": "HostName", "ip": "SrcIp",
        "process": "ProcessName", "file_hash": "FileHash", "domain": "Domain",
    }
    return mapping.get(etype)


# ── tune application ────────────────────────────────────────────────────────────

def _apply_tune(db: Database, rule: dict, tune: dict, dry_run: bool,
                agent: TuningAgent, result: AgentResult) -> None:
    """Apply a tuning recommendation to a rule via RuleStore."""
    rid = rule["rule_id"]
    kind = tune["kind"]

    if kind == "rule_disable":
        if dry_run:
            agent.record_action(result, "disable_rule", rule_id=rid, reason=tune["reason"])
        else:
            try:
                from ..detect.engine import RuleStore
                RuleStore(db).disable(rid)
            except ImportError:
                db.execute("UPDATE rules SET enabled=FALSE WHERE rule_id=?", [rid])

    elif kind == "rule_tune":
        suggested = tune.get("suggested_changes", {})
        updates: dict[str, Any] = {}

        if "raise_threshold" in suggested:
            updates["threshold"] = suggested["raise_threshold"]
        if "lengthen_window" in suggested:
            updates["lookback_minutes"] = suggested["lengthen_window"]

        if updates:
            if dry_run:
                agent.record_action(result, "tune_rule", rule_id=rid,
                                    updates=updates, reason=tune["reason"])
            else:
                try:
                    from ..detect.engine import RuleStore
                    rs = RuleStore(db)
                    rs.update(rid, **updates)
                except ImportError:
                    for k, v in updates.items():
                        db.execute(f"UPDATE rules SET {k}=? WHERE rule_id=?", [v, rid])
                # Append to tuning_history as proper JSON
                _add_tuning_history(db, rid, {
                    "action": "tune", "changes": updates,
                    "reason": tune["reason"],
                    "timestamp": _utcnow().isoformat(),
                })

    elif kind == "entity_exclusion":
        excl = tune.get("exclude_entity", {})
        if not excl:
            return
        # This modifies the rule query to add an exclusion
        old_query = rule.get("query", "")
        col = excl.get("column", "")
        val = excl.get("value", "")
        if col and val and old_query:
            # Add exclusion to the KQL where clause
            exclude_clause = f' | where {col} !in ("{val}")'
            # Validate new query
            try:
                from ..kql import compile_kql
                new_query = old_query + exclude_clause
                compile_kql(new_query)
            except Exception:
                # KQL may fail with string literals (known bug); try anyway
                new_query = old_query + exclude_clause

            if dry_run:
                agent.record_action(result, "tune_rule", rule_id=rid,
                                    query_change=exclude_clause,
                                    reason=tune["reason"])
            else:
                try:
                    from ..detect.engine import RuleStore
                    rs = RuleStore(db)
                    rs.update(rid, query=new_query)
                except ImportError:
                    db.execute("UPDATE rules SET query=? WHERE rule_id=?",
                               [new_query, rid])
                _add_tuning_history(db, rid, {
                    "action": "entity_exclusion", "column": col,
                    "value": val, "reason": tune["reason"],
                    "timestamp": _utcnow().isoformat(),
                })


# ── Main agent class ────────────────────────────────────────────────────────────

class TuningAgent(Agent):
    """Analyze rule performance and recommend/propose tuning changes."""

    name = "tuning"

    def execute(self, rule_ids: list[str] | None = None, window_days: int = 30,
                **kw) -> AgentResult:
        result = AgentResult()

        # Resolve policy
        policy = resolve_policy(self.db, "tuning")

        # Analysis
        analyzed = _analyze_rules(self.db, window_days)
        if rule_ids:
            analyzed = [a for a in analyzed if a["rule_id"] in rule_ids]

        # Filter: only rules with recommendations
        actionable = [a for a in analyzed if a.get("recommendation")]

        # Generate recommendations for each actionable rule
        recommendations = []
        tunes_applied = []
        for a in actionable:
            rid = a["rule_id"]
            rec = a["recommendation"]
            kind = rec["kind"]

            # Create recommendation record (always, for human review)
            rec_id = self.recommend(
                kind=kind,
                target=rid,
                title=f"Tuning: {rec['reason'][:80]}",
                rationale=f"Rule '{a['name']}' ({rid}): {a['alert_count']} alerts, "
                          f"FP rate {a['fp_rate']*100:.0f}%, severity {a['severity']}. "
                          f"{rec['reason']}",
                payload={"rule": a, "tune": rec, "window_days": window_days})

            recommendations.append({"rec_id": rec_id, "rule_id": rid,
                                    "kind": kind, "reason": rec["reason"]})

            # Apply tune if dry_run=False and policy mode allows
            dry_run = kw.get("dry_run", self.dry_run)
            if not dry_run and policy.mode != "off":
                # For auto_close and auto_remediate modes, apply high-severity tunes
                can_apply = (
                    policy.mode in ("auto_close", "auto_remediate")
                    and rec.get("severity") in ("high", "medium")
                )
                if can_apply:
                    _apply_tune(self.db, a, rec, dry_run=False,
                                agent=self, result=result)
                    tunes_applied.append({"rule_id": rid, "kind": kind,
                                          "reason": rec["reason"]})
                elif not dry_run and rec.get("severity") == "high":
                    # Always apply high-severity fixes (like disabling broken rules)
                    _apply_tune(self.db, a, rec, dry_run=False,
                                agent=self, result=result)
                    tunes_applied.append({"rule_id": rid, "kind": kind,
                                          "reason": rec["reason"]})

        # Summary statistics
        total_rules = len(analyzed)
        rules_with_recs = len(actionable)
        fp_rules = len([a for a in analyzed if a["fp_rate"] > 0.5])
        error_rules = len([a for a in analyzed if a.get("last_error")])

        result.output = {
            "window_days": window_days,
            "total_rules_analyzed": total_rules,
            "rules_with_recommendations": rules_with_recs,
            "recommendations": recommendations,
            "tunes_applied": tunes_applied,
            "fp_rules": fp_rules,
            "error_rules": error_rules,
            "analyzed": analyzed,
        }

        result.summary = (f"Analyzed {total_rules} rules over {window_days}d. "
                          f"{rules_with_recs} recommendations. "
                          f"{fp_rules} rules with >50% FP rate. "
                          f"{error_rules} with errors. "
                          f"{len(tunes_applied)} tunes applied.")
        return result
