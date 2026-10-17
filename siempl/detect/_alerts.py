"""Alert creation, entity extraction, incident grouping and the analyst verdict API."""
from __future__ import annotations

from datetime import datetime, timedelta

from ..db import Database, new_id, utcnow
from ._core import _escape_sql_str, _from_json, _json, _json_list


def create_alert(db: Database, rule: dict, rows: list[list],
                 columns: list[str]) -> str | None:
    """Create an alert from rule match results.

    - Deduplicate: same rule + entity set within dedupe window -> update row_count
    - Entity mapping: extract entities from result rows + rule.entity_mappings
    - Entity upserts: bump entity.alert_count
    - alert_number: next value of alert_number_seq (unique, incrementing)
    - Evidence capped at 20 rows (JSON-safe)
    - Bump table_usage.alerts_generated

    Returns alert_id or None (deduplicated update).
    """
    from ..entities import EntityStore

    ents = EntityStore(db)

    # Extract entities from result rows using entity_mappings
    entity_map = _extract_entities_from_rows(rule, rows, columns)

    # Build dedupe key: rule_id + sorted entity values
    dedupe_vals = sorted(f"{t}:{v}" for t, v in sorted(entity_map.items()))
    dedupe_key = f"{rule['rule_id']}:{'|'.join(dedupe_vals)}" if dedupe_vals else rule["rule_id"]

    now = utcnow()
    window = now - timedelta(minutes=int(rule.get("frequency_minutes", 5)) * 3)

    # Check for existing alert within window
    existing = db.query_one(
        "SELECT alert_id, row_count FROM alerts WHERE dedupe_key=? AND created_at >= ? "
        "ORDER BY created_at DESC LIMIT 1",
        [dedupe_key, window])
    if existing:
        db.execute(
            "UPDATE alerts SET row_count = row_count + ?, updated_at = ? WHERE alert_id = ?",
            [len(rows), now, existing["alert_id"]])
        return None  # deduplicated

    # Build alert
    alert_id = new_id("alert_")
    rule_id = rule["rule_id"]
    title = rule.get("name", "Untitled")[:200]
    severity = rule.get("severity", "medium")

    # Evidence: cap at 20 rows
    evidence_raw = [dict(zip(columns, r)) for r in rows[:20]]

    # Entity list for the alert
    entity_list = [{"type": t, "value": v} for t, v in entity_map.items()]

    alert_number = db.query_one("SELECT nextval('alert_number_seq') AS n")["n"]

    # MITRE
    mt = rule.get("mitre_techniques", [])
    if isinstance(mt, str):
        import json as _json_mod
        mt = _json_mod.loads(mt)

    db.execute(
        "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,"
        "created_at,updated_at,window_start,window_end,row_count,evidence,entities,"
        "dedupe_key,mitre_techniques,alert_number) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [alert_id, rule_id, title, severity, "new",
         rule.get("description", ""), now, now,
         now - timedelta(minutes=int(rule.get("lookback_minutes", 5))),
         now, len(rows), _json(evidence_raw), _json(entity_list),
         dedupe_key, _json_list(mt), alert_number])

    # Upsert entities and bump alert_count
    for ent in entity_list:
        eid = ents.upsert(ent["type"], ent["value"])
        db.execute(
            "UPDATE entities SET alert_count = COALESCE(alert_count,0) + 1 WHERE entity_id = ?",
            [eid])

    # Bump table_usage.alerts_generated
    for table in (rule.get("tables") or []):
        if isinstance(table, str):
            db.execute(
                "INSERT INTO table_usage(day,table_name,rows_ingested,bytes_ingested,"
                "rule_queries,user_queries,alerts_generated) VALUES "
                "(CAST(now() AS DATE),?,0,0,0,0,1) "
                "ON CONFLICT (day,table_name) DO UPDATE SET "
                "alerts_generated = table_usage.alerts_generated + 1",
                [table])

    return alert_id


def _extract_entities_from_rows(rule: dict, rows: list[list],
                                columns: list[str]) -> dict[str, str]:
    """Extract entity type->value pairs from result rows using rule.entity_mappings."""
    mappings = rule.get("entity_mappings")
    if isinstance(mappings, str):
        mappings = _from_json(mappings)
    # Handle double-encoding: _json("[]") stores '"[]"', _from_json returns "[]"
    if isinstance(mappings, str):
        mappings = _from_json(mappings)
    if not mappings or not rows or not isinstance(mappings, list):
        return {}

    col_index = {c: i for i, c in enumerate(columns)}
    result: dict[str, str] = {}
    for mapping in mappings:
        etype = mapping.get("entity_type", "")
        col = mapping.get("column", "")
        if not etype or not col:
            continue
        idx = col_index.get(col)
        if idx is None:
            continue
        # Take value from first row that has a non-null value
        for row in rows:
            val = row[idx]
            if val is not None and str(val).strip():
                result[etype] = str(val).strip()
                break
    return result


def _find_or_create_incident(db: Database, entities: list[dict],
                             now: datetime) -> str:
    """Find an open incident sharing any entity in the last 24h, or create one."""
    from ..schema import ENTITY_TYPES

    # Look for open incidents with shared entities
    for ent in (entities or []):
        if ent.get("type") not in ENTITY_TYPES:
            continue
        existing = db.query_one(
            "SELECT a.incident_id FROM alerts a "
            "JOIN incidents i ON a.incident_id = i.incident_id "
            "WHERE i.status = 'new' AND a.created_at >= ? "
            "AND a.entities LIKE ? "
            "ORDER BY a.created_at DESC LIMIT 1",
            [now - timedelta(hours=24),
             f'%{_escape_sql_str(ent["value"])}%'])
        if existing:
            return existing["incident_id"]

    # Create new incident
    incident_id = new_id("inc_")
    sev = "medium"
    if entities:
        sev = "low"

    db.execute(
        "INSERT INTO incidents(incident_id,title,severity,status,created_at,updated_at) "
        "VALUES (?,?,?,?,?,?)",
        [incident_id, f"Incident {incident_id[-8:]}", sev, "new", now, now])
    return incident_id


def set_verdict(db: Database, alert_id: str, verdict: str, by: str) -> bool:
    """Close an alert as true/false positive (compat wrapper over alerts_status.set_status).

    Returns False if the alert is missing or already closed. 'benign' closes as false positive.
    """
    from ..alerts_status import STATUS_FOR_VERDICT, is_closed, set_status

    status = STATUS_FOR_VERDICT.get(verdict)
    if status is None:
        return False
    alert = db.query_one("SELECT status FROM alerts WHERE alert_id=?", [alert_id])
    if not alert or is_closed(alert["status"]):
        return False
    return set_status(db, alert_id, status, by)
