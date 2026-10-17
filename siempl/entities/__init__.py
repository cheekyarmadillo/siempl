"""Entity store: unified entity tracking, reputation, links, and verdict feedback.

Entities are identified by "type:value" (lowercased).  Reputation is a float
0 (benign) .. 100 (malicious), 50 = unknown.  Verdict feedback moves reputation
with diminishing returns and hard ceilings for well-known safe values.

Public API
----------
EntityStore(db)              — wraps a Database
  .upsert(etype, value, ...) -> entity_id
  .link(a_id, b_id, relation) -> None
  .get(entity_id) -> dict | None
  .search(q, etype, order, limit) -> list[dict]
  .apply_verdict(alert_id, verdict, by) -> None   — moves reputation
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from ..db import Database, utcnow
from ..schema import ENTITY_TYPES

# ----------------------------------------------------------------
# Reputation constants
# ----------------------------------------------------------------
MAX_REPUTATION = 100.0
MIN_REPUTATION = 0.0
UNKNOWN_REPUTATION = 50.0

# Per-verdict step size — decreases by DIMINISH_FACTOR each time we move in
# the same direction.  Resets when direction flips.
STEP_BASE = 15.0          # first true_positive / false_positive step
MIN_STEP = 2.5            # never step smaller than this
DIMINISH_FACTOR = 0.75    # multiplier after each same-direction move

# Neutral decay: after each verdict, a one-time decay toward 50 is applied
# before the step.  Fraction of distance moved.
DECAY_FRACTION = 0.1

# Hard ceiling for known-benign values.  Private IPs and well-known safe
# hostnames / users never cross 60 (trend toward benign is clamped).
BENIGN_CEILING = 60.0

# Well-known benign values (clamped, regardless of direction).
WELL_KNOWN_BENIGN = frozenset({
    "host:localhost", "host:127.0.0.1",
    "user:system", "user:root", "user:administrator",
    "ip:127.0.0.1", "ip:0.0.0.0", "ip:255.255.255.255",
    "process:idle", "process:system",
})


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def _is_private_ip(value: str) -> bool:
    """True if *value* is an RFC-1918 / loopback / link-local address."""
    try:
        a = ipaddress.ip_address(value)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _rep_ceiling(etype: str, value: str) -> float:
    """The highest reputation this entity can reach.  None means unlimited."""
    key = f"{etype}:{value.lower()}"
    if key in WELL_KNOWN_BENIGN:
        return BENIGN_CEILING
    if etype == "ip" and _is_private_ip(value):
        return BENIGN_CEILING
    return MAX_REPUTATION  # no ceiling


# ----------------------------------------------------------------
# EntityStore
# ----------------------------------------------------------------

class EntityStore:
    def __init__(self, db: Database):
        self.db = db

    # -- lifecycle -------------------------------------------------------------
    def upsert(self, etype: str, value: str, seen: datetime | None = None,
               event_count: int = 1, table: str | None = None, **attrs) -> str:
        """Create or touch an entity.  Returns the entity_id."""
        if etype not in ENTITY_TYPES:
            raise ValueError(f"Unknown entity type {etype!r}; expected one of {ENTITY_TYPES}")
        eid = f"{etype}:{value.lower()}"
        seen_dt = seen or utcnow()
        existing = self.db.query_one("SELECT * FROM entities WHERE entity_id=?", [eid])
        if existing:
            raw_attrs = existing.get("attributes", {}) or {}
            if isinstance(raw_attrs, str):
                import json
                raw_attrs = json.loads(raw_attrs)
            merged = dict(raw_attrs or {})
            if isinstance(merged, str):
                import json
                merged = json.loads(merged)
            merged.update(attrs)
            self.db.execute(
                "UPDATE entities SET last_seen=?, event_count=event_count+?, attributes=? "
                "WHERE entity_id=?",
                [seen_dt, event_count, _json(merged), eid])
        else:
            self.db.execute(
                "INSERT INTO entities(entity_id,type,value,first_seen,last_seen,event_count,attributes) "
                "VALUES (?,?,?,?,?,?,?)",
                [eid, etype, value, seen_dt, seen_dt, event_count, _json(dict(attrs))])
        # Side table: entity_tables
        if table:
            self._touch_entity_table(eid, table, seen_dt, event_count)
        return eid

    def _touch_entity_table(self, entity_id: str, table: str, seen: datetime, event_count: int = 1) -> None:
        self.db.execute(
            "INSERT INTO entity_tables(entity_id,table_name,first_seen,last_seen,event_count) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT (entity_id,table_name) DO UPDATE SET "
            "last_seen=EXCLUDED.last_seen, event_count=entity_tables.event_count+?",
            [entity_id, table, seen, seen, event_count, event_count])

    def backfill_entity_tables(self) -> dict:
        """One-time lazy backfill: scan all data tables once per (table,column).
        Returns summary dict with counts."""
        from ..schema import COMMON_COLUMNS, DATA_TABLES, ENTITY_COLUMNS
        total = 0
        for table in DATA_TABLES:
            # Collect relevant columns for this table
            table_cols = {c[0] for c in COMMON_COLUMNS}
            table_cols |= {c[0] for c in DATA_TABLES[table].get("columns", [])}
            relevant = [(col, etype) for col, etype in ENTITY_COLUMNS.items() if col in table_cols]
            if not relevant:
                continue
            for col, etype in relevant:
                # Single aggregate per (table,column)
                rows = self.db.query(
                    f'''SELECT "{col}" AS val, MIN(TimeGenerated) AS first_seen,
                        MAX(TimeGenerated) AS last_seen, COUNT(*) AS cnt
                    FROM "{table}" WHERE "{col}" IS NOT NULL AND "{col}" != ''
                    GROUP BY "{col}"'''
                )
                for r in rows:
                    val = r["val"]
                    if not val:
                        continue
                    eid = f"{etype}:{str(val).lower()}"
                    fs = r["first_seen"]
                    ls = r["last_seen"]
                    cnt = int(r["cnt"] or 0)
                    self.db.execute(
                        "INSERT INTO entity_tables(entity_id,table_name,first_seen,last_seen,event_count) "
                        "VALUES (?,?,?,?,?) "
                        "ON CONFLICT (entity_id,table_name) DO UPDATE SET "
                        "last_seen=GREATEST(entity_tables.last_seen, EXCLUDED.last_seen), "
                        "event_count=entity_tables.event_count+EXCLUDED.event_count",
                        [eid, table, fs, ls, cnt])
                    total += 1
        return {"total_pairs_backfilled": total}

    def link(self, a_id: str, b_id: str, relation: str) -> None:
        """Add or refresh an edge between two entities."""
        now = utcnow()
        self.db.execute(
            "INSERT INTO entity_edges(src_entity,dst_entity,relation,first_seen,last_seen,weight) "
            "VALUES (?,?,?,?,?,1) "
            "ON CONFLICT (src_entity,dst_entity,relation) DO UPDATE SET "
            "last_seen=?, weight=entity_edges.weight+1",
            [a_id, b_id, relation, now, now, now])

    # -- queries ----------------------------------------------------------------
    def get(self, entity_id: str) -> dict | None:
        """Return full entity row or None."""
        return self.db.query_one("SELECT * FROM entities WHERE entity_id=?", [entity_id])

    def search(self, q: str | None = None, etype: str | None = None,
               order: str = "reputation DESC", limit: int = 100) -> list[dict]:
        """Search entities.  *q* matches value (ILIKE)."""
        clauses = ["1=1"]
        params: list = []
        if q:
            clauses.append("value ILIKE ?")
            params.append(f"%{q}%")
        if etype:
            clauses.append("type = ?")
            params.append(etype)
        allowed_order = {
            "reputation DESC", "reputation ASC", "last_seen DESC", "last_seen ASC",
            "event_count DESC", "alert_count DESC",
        }
        if order not in allowed_order:
            order = "reputation DESC"
        sql = f"SELECT * FROM entities WHERE {' AND '.join(clauses)} ORDER BY {order} LIMIT ?"
        params.append(limit)
        return self.db.query(sql, params)

    # -- reputation -------------------------------------------------------------

    def apply_verdict(self, alert_id: str, verdict: str, by: str) -> None:
        """Move reputation of every entity in *alert_id*'s entities JSON.

        Verdict  Direction
        -------  -----------------------------------------------
        true_positive  up   (toward 100)
        false_positive down (toward 0)
        benign         down (toward 0)
        unknown        no-op
        """
        if verdict not in ("true_positive", "false_positive", "benign", "unknown"):
            raise ValueError(f"Unknown verdict {verdict!r}")
        if verdict == "unknown":
            return

        alert = self.db.query_one(
            "SELECT entities, verdict FROM alerts WHERE alert_id=?", [alert_id])
        if not alert:
            return

        # Already decided?  Skip double-counting (first verdict only is counted).
        if alert.get("verdict") and alert["verdict"] != "unknown":
            return

        ents = _parse_json_list(alert.get("entities"))
        if not ents:
            return

        direction = 1 if verdict == "true_positive" else -1

        for ent in ents:
            self._move_one_entity(ent["type"], ent["value"], direction)

    # -- internal ---------------------------------------------------------------
    def _move_one_entity(self, etype: str, value: str, direction: int) -> None:
        """Apply a single verdict step to one entity."""
        eid = f"{etype}:{value.lower()}"
        row = self.db.query_one("SELECT * FROM entities WHERE entity_id=?", [eid])
        if not row:
            return

        rep = float(row["reputation"])
        tp_count = int(row["tp_count"] or 0)
        fp_count = int(row["fp_count"] or 0)

        # Which direction was the *last* movement?
        # tp_count > fp_count means we've been pushed up overall
        prev_direction = 1 if tp_count > fp_count else (-1 if fp_count > tp_count else 0)

        # Decay toward 50 (neutral) before applying step
        decay = (UNKNOWN_REPUTATION - rep) * DECAY_FRACTION
        rep += decay

        # Calculate step size: diminishing returns when moving in same direction
        if direction == prev_direction and prev_direction != 0:
            total_moves = tp_count + fp_count
            step = max(MIN_STEP, STEP_BASE * (DIMINISH_FACTOR ** total_moves))
        else:
            step = STEP_BASE

        rep += step * direction

        # Clamp
        ceiling = _rep_ceiling(etype, value)
        rep = max(MIN_REPUTATION, min(ceiling, rep))

        # Update counts
        if direction == 1:
            tp_count += 1
        else:
            fp_count += 1

        self.db.execute(
            "UPDATE entities SET reputation=?, tp_count=?, fp_count=? WHERE entity_id=?",
            [rep, tp_count, fp_count, eid])


# ----------------------------------------------------------------
# JSON helpers
# ----------------------------------------------------------------

def _json(obj: Any) -> str:
    import json
    return json.dumps(obj, default=str)


def _parse_json_list(raw: Any) -> list[dict]:
    import json
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        return json.loads(raw)
    return []
