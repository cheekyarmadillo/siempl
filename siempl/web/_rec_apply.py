"""Helpers for applying agent recommendations (kept out of routes_agents.py, which may not grow)."""
from __future__ import annotations

import json
import re

from ..db import Database, utcnow


def apply_rule_tune(db: Database, rule_id: str, query: str, reason: str) -> None:
    """Replace a rule's query and append a tuning_history entry.

    The history is read and rewritten in Python: DuckDB cannot concatenate a JSON column with a string.
    """
    row = db.query_one("SELECT tuning_history FROM rules WHERE rule_id=?", [rule_id]) or {}
    raw = row.get("tuning_history") or []
    history = json.loads(raw) if isinstance(raw, str) else list(raw)
    history.append({"tuned_at": utcnow().isoformat(), "reason": reason, "query": query})
    db.execute("UPDATE rules SET query=?, tuning_history=?, updated_at=? WHERE rule_id=?",
               [query, json.dumps(history), utcnow(), rule_id])

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _exclusion_from_payload(payload: dict) -> dict:
    """Find the exclude_entity block wherever the tuning agent nested it."""
    for holder in (payload, payload.get("tune") or {}, (payload.get("rule") or {}).get("recommendation") or {}):
        excl = holder.get("exclude_entity") if isinstance(holder, dict) else None
        if isinstance(excl, dict) and excl.get("column") and excl.get("value") not in (None, ""):
            return excl
    return {}


def build_exclusion_query(query: str, column: str, value: str) -> str:
    """Insert `| where <column> !in ("<value>")` right after the source table of a rule query.

    Placing it first keeps it valid for summarize/threshold rules too (it filters rows, not results).
    Raises ValueError on an unsafe column name or a query that does not compile.
    """
    if not _IDENT.match(column):
        raise ValueError(f"unsafe column name {column!r}")
    literal = str(value).replace("\\", "\\\\").replace('"', '\\"')
    clause = f' | where {column} !in ("{literal}")'
    head, sep, rest = query.partition(" | ")
    new_query = head + clause + (sep + rest if sep else "")
    from ..kql import compile_kql
    compile_kql(new_query)  # strict: a rule query that does not compile must never be written
    return new_query


def apply_entity_exclusion(db: Database, rule_id: str, payload: dict, reason: str) -> dict:
    """Apply an entity_exclusion recommendation. Returns {"ok", "message"}; writes nothing on failure."""
    excl = _exclusion_from_payload(payload)
    if not excl:
        return {"ok": False, "message": "entity_exclusion recommendation has no exclude_entity column/value"}
    row = db.query_one("SELECT query FROM rules WHERE rule_id=?", [rule_id])
    if not row or not row.get("query"):
        return {"ok": False, "message": f"rule {rule_id} not found or has no query"}
    try:
        new_query = build_exclusion_query(row["query"], str(excl["column"]), str(excl["value"]))
    except Exception as e:  # noqa: BLE001 - surfaced to the user, nothing was written
        return {"ok": False, "message": f"exclusion not applied: {e}"}
    apply_rule_tune(db, rule_id, new_query, reason)
    return {"ok": True, "message": f"excluded {excl['column']}={excl['value']} from {rule_id}"}


def apply_onboard_source(db: Database, source_id: str, payload: dict) -> dict:
    """Apply an onboard_source recommendation: built-in parser (payload.parser) or proposed mapping spec."""
    spec = payload.get("spec")
    parser, table = payload.get("parser"), payload.get("target_table")
    if isinstance(spec, dict):
        from ..ingest.mapping import _register_mapping, validate_spec
        errors = validate_spec(spec)
        if errors:
            return {"ok": False, "message": "mapping spec invalid: " + "; ".join(errors[:3])}
        parser, table = spec["name"], spec["target_table"]
        db.execute("INSERT OR REPLACE INTO parsers(name, spec, target_table, origin, sample) VALUES (?,?,?,?,?)",
                   [parser, json.dumps(spec), table, "ai", json.dumps(spec.get("fields", {}))])
        _register_mapping(spec)
    if not parser or not table:
        return {"ok": False, "message": "onboard_source recommendation has no parser/spec to apply"}
    db.execute("UPDATE sources SET parser=?, target_table=?, status='active' WHERE source_id=?",
               [parser, table, source_id])
    return {"ok": True, "message": f"source {source_id} now uses parser {parser}"}



SPECIAL_KINDS = ("onboard_source", "entity_exclusion")


def apply_special_kind(db: Database, kind: str, target: str, payload: dict, reason: str) -> dict:
    """Dispatch for the recommendation kinds whose apply logic lives here."""
    res = (apply_entity_exclusion(db, target, payload, reason) if kind == "entity_exclusion"
           else apply_onboard_source(db, target, payload))
    if not res["ok"]:
        raise ValueError(res["message"])
    return res
