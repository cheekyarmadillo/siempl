"""Alert-model migrations: alerts and incidents merged into one object. Run by Database.init_schema().

Not for: the status rules (alerts_status.py) or the HTTP API (web/routes_alerts_api.py).
Every step is idempotent. Column adds use IF NOT EXISTS, numbering only fills NULL alert_number,
and the incident merge runs once, guarded by settings key MERGE_KEY and inside one transaction.
Incident tables and alerts.incident_id are kept as legacy data and are no longer written.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from .alerts_status import CLOSED_STATUSES, derived_verdict, normalize_legacy

if TYPE_CHECKING:
    from .db import Database

logger = logging.getLogger(__name__)

MERGE_KEY = "alerts_merged_v1"
MERGE_AUTHOR = "system"

ALERT_COLUMN_MIGRATIONS: list[str] = [
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS alert_number BIGINT",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS owner VARCHAR",
    "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reputation_applied BOOLEAN DEFAULT FALSE",
]

# incident_comments was created lazily by the retired incidents router. Fresh databases lack it,
# so the merge creates it (empty) before reading it.
INCIDENT_COMMENTS_DDL = """
CREATE TABLE IF NOT EXISTS incident_comments (
  comment_id VARCHAR PRIMARY KEY, incident_id VARCHAR, author VARCHAR, body VARCHAR, ts TIMESTAMP DEFAULT now());
"""


def migrate_alerts(db: Database) -> None:
    """Bring an alerts table of any age to the current model. Raises on failure (no swallowing)."""
    from .db import utcnow  # local import: db.py imports this module from init_schema

    with db.write_lock:
        for stmt in ALERT_COLUMN_MIGRATIONS:
            db.conn.execute(stmt)
        _number_alerts(db)
        if not db.get_setting(MERGE_KEY, False):
            _merge_incidents(db, utcnow())


def _number_alerts(db: Database) -> None:
    """Give every alert without alert_number a number in (created_at, alert_id) order, then create the
    sequence that hands out the next one. The unique index makes a duplicate number a hard error."""
    conn = db.conn
    top = _max_alert_number(db)
    conn.execute(
        "UPDATE alerts SET alert_number = numbered.n FROM ("
        "  SELECT alert_id, ? + row_number() OVER (ORDER BY created_at, alert_id) AS n"
        "  FROM alerts WHERE alert_number IS NULL) AS numbered "
        "WHERE alerts.alert_id = numbered.alert_id", [top])
    conn.execute("CREATE SEQUENCE IF NOT EXISTS alert_number_seq START WITH 1")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS alerts_alert_number_uq ON alerts(alert_number)")
    # A fresh sequence must start above the highest number in use. An existing one is left alone.
    if conn.execute("SELECT last_value FROM duckdb_sequences() WHERE sequence_name='alert_number_seq'"
                    ).fetchone()[0] is None and _max_alert_number(db) > 0:
        conn.execute("DROP SEQUENCE alert_number_seq")
        conn.execute(f"CREATE SEQUENCE alert_number_seq START WITH {_max_alert_number(db) + 1}")


def _max_alert_number(db: Database) -> int:
    return int(db.conn.execute("SELECT coalesce(max(alert_number), 0) FROM alerts").fetchone()[0])


def _merge_incidents(db: Database, now) -> None:
    """One-time merge: incident owner and comments onto alerts, legacy statuses converted.

    Runs in a single transaction on db.conn. Cursors are separate DuckDB connections and would not be
    part of it, so every statement here goes through db.conn.
    """
    conn = db.conn
    conn.execute("BEGIN TRANSACTION")
    try:
        conn.execute(INCIDENT_COMMENTS_DDL)
        _copy_incident_owners(conn)
        _copy_incident_comments(conn, now)
        _normalize_statuses(conn)
        conn.execute("INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES (?,?,?)",
                     [MERGE_KEY, json.dumps(True), now])
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    logger.info("alerts merge: incidents folded into alerts (%s)", MERGE_KEY)

def _copy_incident_owners(conn) -> None:
    """alerts.owner <- owner of the alert's former incident (only where the alert has none)."""
    conn.execute(
        "UPDATE alerts SET owner = i.owner FROM incidents i "
        "WHERE alerts.incident_id = i.incident_id AND alerts.owner IS NULL AND i.owner IS NOT NULL")


def _copy_incident_comments(conn, now) -> None:
    """Incident comments and a one-line summary become comments on each member alert."""
    conn.execute(
        "INSERT INTO alert_comments(comment_id, alert_id, author, body, ts) "
        "SELECT 'mig_' || c.comment_id || '_' || a.alert_id, a.alert_id, c.author, "
        "'[from incident ' || c.incident_id || '] ' || coalesce(c.body, ''), c.ts "
        "FROM incident_comments c JOIN alerts a ON a.incident_id = c.incident_id "
        "WHERE NOT EXISTS (SELECT 1 FROM alert_comments x "
        "WHERE x.comment_id = 'mig_' || c.comment_id || '_' || a.alert_id)")
    conn.execute(
        "INSERT INTO alert_comments(comment_id, alert_id, author, body, ts) "
        "SELECT 'mig_sum_' || a.alert_id, a.alert_id, ?, "
        "'Migrated from incident ' || i.incident_id || ': ' || coalesce(i.title, '') || "
        "' - ' || coalesce(i.summary, ''), ? "
        "FROM alerts a JOIN incidents i ON a.incident_id = i.incident_id "
        "WHERE NOT EXISTS (SELECT 1 FROM alert_comments x WHERE x.comment_id = 'mig_sum_' || a.alert_id)",
        [MERGE_AUTHOR, now])


def _normalize_statuses(conn) -> None:
    """Convert every legacy status (triaging/escalated/closed) and derive the internal verdict column."""
    rows = conn.execute("SELECT alert_id, status, verdict FROM alerts").fetchall()
    for alert_id, status, verdict in rows:
        new = normalize_legacy(status, verdict)
        applied = new in CLOSED_STATUSES and verdict in ("true_positive", "false_positive", "benign")
        conn.execute(
            "UPDATE alerts SET status=?, verdict=?, reputation_applied=? WHERE alert_id=?",
            [new, derived_verdict(new), applied, alert_id])
