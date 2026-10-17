"""Alert status model: the four statuses, legacy mapping, and the single write path for status and severity.

Statuses: new | active | closed_tp | closed_fp.  "Open" means new or active.
Not for: HTTP handling (web/routes_alerts_api.py) or creating alerts (detect/_alerts.py).

Every application write to alerts.status, alerts.severity or alerts.owner goes through set_status() /
set_severity() / set_owner().
Those functions keep three things consistent: the audit trail (SiemplAudit), the internal legacy column
alerts.verdict (derived from status, read by older agent/entity SQL), and entity reputation (applied once,
on the first entry into closed_tp/closed_fp; see EntityStore.apply_verdict).

    from siempl.alerts_status import set_status
    set_status(db, alert_id, "closed_tp", "user:web")   # -> True, or False if no such alert
"""
from __future__ import annotations

from .audit import record
from .db import Database, utcnow
from .entities import EntityStore

STATUSES: tuple[str, ...] = ("new", "active", "closed_tp", "closed_fp")
OPEN_STATUSES: tuple[str, ...] = ("new", "active")
CLOSED_STATUSES: tuple[str, ...] = ("closed_tp", "closed_fp")
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")

# Derived, internal only: what alerts.verdict is kept in sync with.
_VERDICT_FOR_STATUS: dict[str, str] = {"closed_tp": "true_positive", "closed_fp": "false_positive"}
# Compat callers (old verdict API, set_verdict) speak verdicts; benign folds into closed_fp.
STATUS_FOR_VERDICT: dict[str, str] = {"true_positive": "closed_tp", "false_positive": "closed_fp",
                                      "benign": "closed_fp"}


class InvalidStatus(ValueError):
    """Status is not one of STATUSES."""


class InvalidSeverity(ValueError):
    """Severity is not one of SEVERITIES."""


OWNER_MAX_LENGTH = 80


def is_open(status: str | None) -> bool:
    return status in OPEN_STATUSES


def is_closed(status: str | None) -> bool:
    return status in CLOSED_STATUSES


def derived_verdict(status: str | None) -> str | None:
    """The internal alerts.verdict value for a status: closed_tp/closed_fp map, everything else is NULL."""
    return _VERDICT_FOR_STATUS.get(status or "")


def normalize_legacy(status: str | None, verdict: str | None) -> str:
    """Map a pre-merge alerts.status (plus its legacy verdict) onto the current statuses.

    triaging and escalated become active. closed becomes closed_tp only when the legacy verdict was
    true_positive; every other closed value (false_positive, benign, unknown, NULL) becomes closed_fp.
    A missing or unrecognised status becomes new. Current statuses pass through unchanged.
    """
    if status in STATUSES:
        return status  # type: ignore[return-value]
    if status in ("triaging", "escalated"):
        return "active"
    if status == "closed":
        return "closed_tp" if verdict == "true_positive" else "closed_fp"
    return "new"


def set_status(db: Database, alert_id: str, status: str, by: str) -> bool:
    """Move an alert to *status*. Returns False if the alert does not exist; raises InvalidStatus.

    Side effects, all under db.write_lock:
    - alerts.status, updated_at, and the derived verdict/verdict_by columns are written.
    - Entering closed_tp/closed_fp applies entity reputation via apply_verdict. That is a no-op after the
      first time, so close-reopen-close never moves reputation twice.
    - One SiemplAudit row, action "alert.status", with from/to in details.
    *by* is the actor string, "user:<name>" or "agent:<name>".
    """
    if status not in STATUSES:
        raise InvalidStatus(f"Invalid status: {status!r}")
    with db.write_lock:
        row = db.query_one("SELECT status, reputation_applied FROM alerts WHERE alert_id=?", [alert_id])
        if row is None:
            return False
        old = row["status"]
        closed = is_closed(status)
        # Reputation moves once per alert, even after a reopen (which clears the derived verdict).
        applied = bool(row.get("reputation_applied"))
        if closed and not applied:
            EntityStore(db).apply_verdict(alert_id, _VERDICT_FOR_STATUS[status], by)
        db.execute(
            "UPDATE alerts SET status=?, verdict=?, verdict_by=?, updated_at=?, reputation_applied=? "
            "WHERE alert_id=?",
            [status, derived_verdict(status), by if closed else None, utcnow(), applied or closed, alert_id])
        record(db, by, "alert.status", "alert", alert_id, details={"from": old, "to": status})
    return True


def set_severity(db: Database, alert_id: str, severity: str, by: str) -> bool:
    """Change an alert's severity. Returns False if the alert does not exist; raises InvalidSeverity.

    Writes alerts.severity and updated_at, and records one audit row, action "alert.severity".
    """
    if severity not in SEVERITIES:
        raise InvalidSeverity(f"Invalid severity: {severity!r}")
    with db.write_lock:
        row = db.query_one("SELECT severity FROM alerts WHERE alert_id=?", [alert_id])
        if row is None:
            return False
        db.execute("UPDATE alerts SET severity=?, updated_at=? WHERE alert_id=?",
                   [severity, utcnow(), alert_id])
        record(db, by, "alert.severity", "alert", alert_id,
               details={"from": row["severity"], "to": severity})
    return True


def set_owner(db: Database, alert_id: str, owner: str | None, by: str) -> bool:
    """Set or clear (None) an alert's owner. Returns False if the alert does not exist.

    The caller validates the value (type and OWNER_MAX_LENGTH). Writes alerts.owner and updated_at,
    and records one audit row, action "alert.owner", with from/to in details.
    """
    with db.write_lock:
        row = db.query_one("SELECT owner FROM alerts WHERE alert_id=?", [alert_id])
        if row is None:
            return False
        db.execute("UPDATE alerts SET owner=?, updated_at=? WHERE alert_id=?", [owner, utcnow(), alert_id])
        record(db, by, "alert.owner", "alert", alert_id, details={"from": row["owner"], "to": owner})
    return True
