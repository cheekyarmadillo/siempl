"""Scenario sample data: multi-step attack chains, noise and injection cases for agent evaluation.

load_scenarios(db, now=None) -> summary dict
  Idempotent. A scenario is skipped when its sources already exist. Rows are written through the
  normal paths: events via Database.insert_events, rules via RuleStore, alerts via create_alert,
  statuses via alerts_status.set_status.
reset_scenarios(db) -> summary dict
  Removes only scenario-tagged rows: SourceId 'scn-%', rule ids 'scn_%', the alerts and comments
  they produced, entities created by them, and their table_usage bumps (today's row, best effort).
scenario_manifest() -> dict
  Expected triage per alert, read from scenarios_manifest.json (the source of truth for evaluation).

Not for: the basic sample set (testdata/sample.py) or real ingest. Scenario builders live in
_scn_attack.py, _scn_movement.py, _scn_noise.py and _scn_injection.py; helpers in _scn_rows.py.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..alerts_status import set_status
from ..audit import record as audit_record
from ..db import Database, utcnow
from ..detect import RuleStore, create_alert
from ..schema import DATA_TABLES
from . import _scn_attack, _scn_injection, _scn_movement, _scn_noise

MANIFEST_PATH = Path(__file__).with_name("scenarios_manifest.json")
TAG_SOURCE = "scn-%"
TAG_RULE = "scn_%"


def _builders() -> list:
    """Scenario builders in load order. Each takes 'now' and returns a scenario() spec."""
    return [
        _scn_attack.brute_force_to_compromise,
        _scn_movement.lateral_movement,
        _scn_movement.data_exfil,
        _scn_noise.noisy_false_positive,
        _scn_injection.prompt_injection_attempts,
        _scn_noise.chatty_source,
        _scn_noise.new_unparsed_source,
    ]


def _now_or_default(now: datetime | None) -> datetime:
    return now if now is not None else utcnow()


def scenario_manifest() -> dict[str, Any]:
    """Expected triage per scenario alert. Read from scenarios_manifest.json; no DB access."""
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _scenario_loaded(db: Database, spec: dict) -> bool:
    """True when every source of the scenario already exists (the idempotency marker)."""
    for src in spec["sources"]:
        if db.query_one("SELECT 1 AS found FROM sources WHERE source_id=?", [src["source_id"]]) is None:
            return False
    return True


def _insert_sources(db: Database, spec: dict, counts: Counter) -> int:
    for src in spec["sources"]:
        db.execute(
            "INSERT INTO sources(source_id,name,kind,parser,target_table,status,events_total,notes,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [src["source_id"], src["name"], src["kind"], src["parser"], src["target_table"], src["status"],
             counts[src["source_id"]], "scenario", utcnow()])
    return len(spec["sources"])


def _insert_events(db: Database, spec: dict) -> Counter:
    """Write event rows grouped by table. Returns row counts per SourceId."""
    by_table: dict[str, list[dict]] = {}
    for table, row in spec["events"]:
        by_table.setdefault(table, []).append(row)
    for table, rows in by_table.items():
        db.insert_events(table, rows)
    return Counter(row["SourceId"] for _, row in spec["events"])


def _insert_rules(db: Database, spec: dict) -> dict[str, dict]:
    """Create rules that do not exist yet. Returns rule_id -> rule dict for alert creation."""
    store = RuleStore(db)
    by_id: dict[str, dict] = {}
    for rule in spec["rules"]:
        by_id[rule["rule_id"]] = rule
        if store.get(rule["rule_id"]) is None:
            store.create(dict(rule))
    return by_id


def _entity_ids(db: Database) -> set[str]:
    return {r["entity_id"] for r in db.query("SELECT entity_id FROM entities")}


def _alert_entity_ids(db: Database, alert_ids: list[str]) -> set[str]:
    eids: set[str] = set()
    for aid in alert_ids:
        row = db.query_one("SELECT entities FROM alerts WHERE alert_id=?", [aid])
        ents = json.loads(row["entities"]) if row and row["entities"] else []
        for ent in ents:
            eids.add(f"{ent['type']}:{str(ent['value']).lower()}")
    return eids


def _create_alerts(db: Database, spec: dict, rules: dict[str, dict], now: datetime) -> list[str]:
    """Create each alert through create_alert, backdate it into the window, then set its status."""
    ids: list[str] = []
    for a in spec["alerts"]:
        cols = a["cols"]
        rows = [[e.get(c) for c in cols] for e in a["evidence"][:20]]
        aid = create_alert(db, rules[a["rule_id"]], rows, cols)
        if aid is None:
            raise RuntimeError(f"scenario alert deduplicated unexpectedly: {a['rule_id']}")
        created = now - timedelta(minutes=a["minutes_ago"])
        db.execute(
            "UPDATE alerts SET created_at=?, updated_at=?, window_start=?, window_end=?, row_count=? "
            "WHERE alert_id=?",
            [created, created, created - timedelta(minutes=60), created, a["count"], aid])
        if a["status"] != "new":
            set_status(db, aid, a["status"], a["by"])
        ids.append(aid)
    return ids


def _tag_new_entities(db: Database, name: str, before: set[str], alert_ids: list[str]) -> int:
    """Mark entities this scenario created (not pre-existing ones) so reset can delete them."""
    fresh = _alert_entity_ids(db, alert_ids) - before
    for eid in fresh:
        db.execute("UPDATE entities SET notes=? WHERE entity_id=?", [f"scn-{name}", eid])
    return len(fresh)


def _load_one(db: Database, spec: dict, now: datetime) -> dict[str, int]:
    """Write one scenario in a single write lock. Returns its counts."""
    with db.write_lock:
        counts = _insert_events(db, spec)
        sources = _insert_sources(db, spec, counts)
        rules = _insert_rules(db, spec)
        before = _entity_ids(db)
        alert_ids = _create_alerts(db, spec, rules, now)
        entities = _tag_new_entities(db, spec["name"], before, alert_ids)
    return {"sources": sources, "rules": len(rules), "events": sum(counts.values()),
            "alerts": len(alert_ids), "entities": entities}


def load_scenarios(db: Database, now: datetime | None = None) -> dict[str, Any]:
    """Load all scenarios that are not loaded yet. Returns totals and per-scenario counts."""
    when = _now_or_default(now)
    summary: dict[str, Any] = {"loaded": [], "skipped": [], "scenarios": {}}
    for build in _builders():
        spec = build(when)
        if _scenario_loaded(db, spec):
            summary["skipped"].append(spec["name"])
            continue
        summary["scenarios"][spec["name"]] = _load_one(db, spec, when)
        summary["loaded"].append(spec["name"])
    if summary["loaded"]:
        audit_record(db, "system", "scenarios.load", target_type="setting", target_id="scenarios",
                     outcome="ok", details={"loaded": summary["loaded"]})
    return summary


def _in_clause(ids: list[str]) -> str:
    return ",".join("?" * len(ids))


def _scenario_alerts(db: Database) -> list[dict]:
    return db.query("SELECT alert_id, rule_id FROM alerts WHERE substr(rule_id,1,4)='scn_'")


def _undo_table_usage(db: Database, alerts: list[dict]) -> None:
    """Reverse create_alert's table_usage bump: today's row, one per (alert, rule table). Best effort."""
    tables_by_rule = {r["rule_id"]: r.get("tables") or [] for r in db.query(
        "SELECT rule_id, tables FROM rules WHERE substr(rule_id,1,4)='scn_'")}
    for alert_row in alerts:
        for table in tables_by_rule.get(alert_row["rule_id"], []):
            db.execute("UPDATE table_usage SET alerts_generated = GREATEST(alerts_generated - 1, 0) "
                       "WHERE day = CAST(now() AS DATE) AND table_name = ?", [table])


def _delete_alert_rows(db: Database, alert_ids: list[str]) -> None:
    """Delete alerts plus the comments, remediation log and alert audit rows that point at them."""
    if not alert_ids:
        return
    marks = _in_clause(alert_ids)
    db.execute(f"DELETE FROM alert_comments WHERE alert_id IN ({marks})", alert_ids)
    db.execute(f"DELETE FROM remediation_log WHERE alert_id IN ({marks})", alert_ids)
    db.execute(f"DELETE FROM SiemplAudit WHERE TargetType='alert' AND TargetId IN ({marks})", alert_ids)
    db.execute(f"DELETE FROM alerts WHERE alert_id IN ({marks})", alert_ids)


def _delete_entities(db: Database) -> int:
    rows = db.query("SELECT entity_id FROM entities WHERE notes LIKE 'scn-%'")
    ids = [r["entity_id"] for r in rows]
    if ids:
        marks = _in_clause(ids)
        db.execute(f"DELETE FROM entity_tables WHERE entity_id IN ({marks})", ids)
        db.execute(f"DELETE FROM entity_edges WHERE src_entity IN ({marks}) OR dst_entity IN ({marks})", ids + ids)
        db.execute(f"DELETE FROM entities WHERE entity_id IN ({marks})", ids)
    return len(ids)


def _delete_events(db: Database) -> dict[str, int]:
    """Delete scenario rows from every data table. Returns rows deleted per table."""
    deleted: dict[str, int] = {}
    for table in DATA_TABLES:
        n = db.query_one(f'SELECT count(*) AS n FROM "{table}" WHERE SourceId LIKE ?', [TAG_SOURCE])["n"]
        if n:
            db.execute(f'DELETE FROM "{table}" WHERE SourceId LIKE ?', [TAG_SOURCE])
        deleted[table] = int(n)
    return deleted


def reset_scenarios(db: Database) -> dict[str, Any]:
    """Remove every scenario-tagged row. Idempotent: a second call deletes nothing."""
    with db.write_lock:
        alerts = _scenario_alerts(db)
        _undo_table_usage(db, alerts)
        _delete_alert_rows(db, [a["alert_id"] for a in alerts])
        entities = _delete_entities(db)
        events = _delete_events(db)
        sources = db.query_one("SELECT count(*) AS n FROM sources WHERE source_id LIKE ?", [TAG_SOURCE])["n"]
        db.execute("DELETE FROM sources WHERE source_id LIKE ?", [TAG_SOURCE])
        rules = db.query_one("SELECT count(*) AS n FROM rules WHERE substr(rule_id,1,4)='scn_'")["n"]
        db.execute("DELETE FROM rules WHERE substr(rule_id,1,4)='scn_'")
    summary: dict[str, Any] = {"alerts_deleted": len(alerts), "rules_deleted": int(rules),
                               "entities_deleted": entities, "sources_deleted": int(sources),
                               "events_deleted": events, "events_total": sum(events.values())}
    if summary["alerts_deleted"] or summary["events_total"] or summary["rules_deleted"]:
        audit_record(db, "system", "scenarios.reset", target_type="setting", target_id="scenarios",
                     outcome="ok", details=summary)
    return summary
