"""Audit log: every action by a user or agent inside siempl is written to the SiemplAudit table.

SiemplAudit is a normal event table, so it is queryable with KQL and usable by rules.

    from siempl.audit import record
    record(db, "user:web", "rule.create", "rule", rule_id, details={"name": name})
    record(db, "agent:triage", "alert.close", "alert", alert_id, outcome="dry_run")

record() never raises: auditing must not break the action being audited.
"""
from __future__ import annotations

import json
import logging

from .db import Database, utcnow

log = logging.getLogger(__name__)


def record(db: Database, actor: str, action: str, target_type: str | None = None,
           target_id: str | None = None, outcome: str = "ok", details: dict | None = None) -> None:
    try:
        actor_type = actor.split(":", 1)[0] if ":" in actor else "system"
        if actor_type not in ("user", "agent", "system"):
            actor_type = "system"
        now = utcnow()
        db.insert_events("SiemplAudit", [{
            "TimeGenerated": now, "IngestTime": now, "SourceId": "siempl", "SourceType": "siempl_audit",
            "EventCode": action, "EventAction": action,
            "EventResult": "success" if outcome in ("ok", "dry_run") else "failure",
            "UserName": actor if actor_type == "user" else None,
            "Message": f"{actor} {action} {target_type or ''} {target_id or ''}".strip(),
            "RawEvent": json.dumps({"actor": actor, "action": action, "target_type": target_type,
                                    "target_id": target_id, "outcome": outcome, "details": details or {}}, default=str),
            "Extra": json.loads(json.dumps(details or {}, default=str)),
            "Actor": actor, "ActorType": actor_type, "Action": action,
            "TargetType": target_type, "TargetId": target_id, "Outcome": outcome,
        }])
    except Exception:  # noqa: BLE001
        log.exception("audit record failed")
