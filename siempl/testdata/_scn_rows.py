"""Row, rule and alert-spec builders shared by the scenario definition modules (_scn_*.py).

Not for: choosing which scenarios exist (scenarios.py), or writing rules/alerts to the DB
(scenarios.py does that through RuleStore, create_alert and set_status).
Every scenario row carries SourceId 'scn-<name>' and every rule id starts with 'scn_', so
reset_scenarios() can remove them without touching sample or real data.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

SOURCE_PREFIX = "scn-"
RULE_PREFIX = "scn_"


def ev(source_id: str, now: datetime, minutes_ago: float, src_type: str = "windows_json", **cols: Any) -> dict:
    """One event row dict. TimeGenerated = now - minutes_ago (naive UTC)."""
    row: dict[str, Any] = {
        "TimeGenerated": now - timedelta(minutes=minutes_ago),
        "SourceId": source_id,
        "SourceType": src_type,
    }
    row.update(cols)
    return row


def source(source_id: str, name: str, parser: str, target_table: str, status: str = "active") -> dict:
    """A sources-table row for a scenario log feed."""
    if not source_id.startswith(SOURCE_PREFIX):
        raise ValueError(f"scenario source must start with {SOURCE_PREFIX!r}: {source_id}")
    return {"source_id": source_id, "name": name, "kind": "syslog", "parser": parser,
            "target_table": target_table, "status": status}


def rule(rule_id: str, name: str, description: str, steps: str, severity: str, query: str,
         tables: list[str], mitre: list[str], mapping: list[dict], threshold: int = 1) -> dict:
    """A detection rule dict in the shape RuleStore.create() accepts. Rule ids are tagged scn_."""
    if not rule_id.startswith(RULE_PREFIX):
        raise ValueError(f"scenario rule id must start with {RULE_PREFIX!r}: {rule_id}")
    return {
        "rule_id": rule_id, "name": name, "description": description, "triage_steps": steps,
        "severity": severity, "query": query, "tables": tables, "frequency_minutes": 5,
        "lookback_minutes": 60, "threshold": threshold, "mitre_techniques": mitre,
        "mitre_tactics": [], "entity_mappings": mapping, "enabled": True, "origin": "manual",
    }


def alert(rule_id: str, evidence: list[dict], cols: list[str], count: int, minutes_ago: float,
          status: str = "new", by: str = "user:scenario-loader") -> dict:
    """An alert spec. evidence = event row dicts; cols = columns kept in the evidence JSON.

    status other than 'new' is applied with set_status(by=...) after creation.
    """
    return {"rule_id": rule_id, "evidence": evidence, "cols": cols, "count": count,
            "minutes_ago": minutes_ago, "status": status, "by": by}


def scenario(name: str, sources: list[dict], rules: list[dict], events: list[tuple[str, dict]],
             alerts: list[dict]) -> dict:
    """Assemble one scenario spec. events = [(table, row_dict), ...]."""
    return {"name": name, "sources": sources, "rules": rules, "events": events, "alerts": alerts}
