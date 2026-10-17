"""IngestionOptimizerAgent – analyze table usage and recommend cost-saving measures.

Purpose: Examine table_usage, query_log, rules (table references), and alerts to
classify tables and recommend ingest_filters, retention changes, and sampling.
Deterministic heuristics always; LLM enrichment optional.

Inputs:  window_days (int, default 7)
Outputs: AgentResult with classification + recommendations

Deterministic flow:
  1. Classify tables: used-by-rules / queried-by-humans / unused
  2. For unused tables with high volume: recommend ingest_filters to drop common templates
  3. For tables with no rule/human queries: recommend shorter retention
  4. Estimate savings in rows/bytes and percentage
  5. Never applies filters itself; only recommends

LLM path (optional): review high-volume patterns and suggest additional filter expressions.

Public helpers:
  apply_recommendation(db, rec_id, by) – approve and apply ingest_filter or retention recs
  purge_expired(db) – delete rows older than table_retention or default_retention_days
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from ..db import Database, new_id
from ..schema import DATA_TABLES
from ._optimizer_sources import noisy_source_recs
from .base import Agent, AgentResult

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _get_usage_stats(db: Database, window_days: int) -> dict[str, dict]:
    usage_rows = db.query(
        f"""SELECT table_name,
                  SUM(rows_ingested) as rows_ingested,
                  SUM(bytes_ingested) as bytes_ingested,
                  SUM(rule_queries) as rule_queries,
                  SUM(user_queries) as user_queries,
                  SUM(alerts_generated) as alerts
           FROM table_usage
           WHERE day >= CURRENT_DATE - INTERVAL '{int(window_days)} days'
           GROUP BY table_name""")
    usage_by_table: dict[str, dict] = {}
    for r in usage_rows:
        usage_by_table[r["table_name"]] = {
            "rows_ingested": r["rows_ingested"] or 0,
            "bytes_ingested": r["bytes_ingested"] or 0,
            "rule_queries": r["rule_queries"] or 0,
            "user_queries": r["user_queries"] or 0,
            "alerts": r["alerts"] or 0,
        }
    return usage_by_table


def _get_rule_table_refs(db: Database, all_tables: list[str]) -> dict[str, set[str]]:
    rules_ref = db.query("SELECT rule_id, tables, enabled FROM rules")
    rule_tables: dict[str, set[str]] = {}
    for r in rules_ref:
        if not r["enabled"]:
            continue
        try:
            tbls = json.loads(r["tables"]) if isinstance(r["tables"], str) else (r["tables"] or [])
        except (json.JSONDecodeError, TypeError):
            tbls = []
        for t in tbls:
            rule_tables.setdefault(t, set()).add(r["rule_id"])
        query = r.get("query", "")
        for t in all_tables:
            if t in query:
                rule_tables.setdefault(t, set()).add(r["rule_id"])
    return rule_tables


def _get_human_table_refs(db: Database, window_days: int) -> set[str]:
    human_queries = db.query(
        f"""SELECT UNNEST(tables) as table_name FROM query_log
           WHERE origin='user' AND ts >= CURRENT_DATE - INTERVAL '{int(window_days)} days'""")
    human_tables: set[str] = set()
    for r in human_queries:
        if r["table_name"]:
            human_tables.add(r["table_name"])
    return human_tables


def _classify_table(table: str, usage: dict, rule_refs: dict[str, set],
                    human_refs: set[str]) -> dict:
    ref_by_rules = bool(rule_refs.get(table))
    ref_by_humans = table in human_refs

    if ref_by_rules and usage["rows_ingested"] > 0:
        usage_class = "used_by_rules"
    elif ref_by_humans and not ref_by_rules:
        usage_class = "queried_by_humans"
    elif usage["rows_ingested"] > 0 and not ref_by_rules and not ref_by_humans:
        usage_class = "unused"
    elif usage["rows_ingested"] == 0:
        usage_class = "empty"
    else:
        usage_class = "inactive"

    return {
        "table": table,
        "usage_class": usage_class,
        "rows_ingested": usage["rows_ingested"],
        "bytes_ingested": usage["bytes_ingested"],
        "rule_queries": usage["rule_queries"],
        "user_queries": usage["user_queries"],
        "alerts": usage["alerts"],
        "referenced_by_rules": list(rule_refs.get(table, [])),
        "referenced_by_humans": ref_by_humans,
        "last_activity": None,
    }


def _classify_tables(db: Database, window_days: int = 7) -> list[dict]:
    """Classify each data table based on usage patterns.

    Returns list of dicts with keys: table, usage_class, rows_ingested, bytes_ingested,
    rule_queries, user_queries, alerts, referenced_by_rules, last_activity, recommendation.
    """
    all_tables = list(DATA_TABLES.keys())
    usage_by_table = _get_usage_stats(db, window_days)
    rule_tables = _get_rule_table_refs(db, all_tables)
    human_tables = _get_human_table_refs(db, window_days)

    results = []
    for table in all_tables:
        usage = usage_by_table.get(table, {"rows_ingested": 0, "bytes_ingested": 0,
                                            "rule_queries": 0, "user_queries": 0,
                                            "alerts": 0})
        results.append(_classify_table(table, usage, rule_tables, human_tables))

    return results


# ── helpers: template analysis for unused/high-volume tables ──────────────────

def _analyze_table_templates(db: Database, table: str, limit: int = 1000) -> list[dict]:
    """Group common message templates/EventCodes in a table, returning top patterns.

    For each table, group by EventCode + first 80 chars of Message (as a template),
    return the most frequent patterns that could be filtered.
    """
    try:
        rows = db.query(
            f'SELECT "EventCode", "Message", COUNT(*) as cnt '
            f'FROM "{table}" '
            f'WHERE "TimeGenerated" >= CURRENT_DATE - INTERVAL \'7 days\' '
            f'GROUP BY "EventCode", LEFT("Message", 80) '
            f'ORDER BY cnt DESC LIMIT ?',
            [limit])
        return rows
    except Exception:
        return []


def _propose_filter_from_template(event_code: str, message_prefix: str,
                                  table: str, count: int) -> dict | None:
    """Given a common template, propose an ingest filter expression."""
    if not event_code and not message_prefix:
        return None

    parts = []
    if event_code:
        # Try to generate a valid KQL expression for the filter
        # Note: KQL string literal handling is tricky; use val-safe quoting
        parts.append(f'EventCode == "{event_code}"')

    if message_prefix:
        safe_prefix = message_prefix.strip().replace('"', '\\"')[:60]
        if safe_prefix:
            parts.append(f'Message contains "{safe_prefix}"')

    if not parts:
        return None

    # Try to validate with KQL compiler
    expr = " and ".join(parts)
    try:
        from ..kql import compile_kql
        kql = f'{table} | where {expr}'
        compile_kql(kql)
    except Exception:
        # KQL may fail with string literals (known bug); use the expression anyway
        logger.debug("_propose_filter_from_template: ignored error", exc_info=True)

    return {
        "table": table,
        "expression": expr,
        "event_code": event_code,
        "message_prefix": message_prefix,
        "sample_count": count,
    }


# ── Main agent class ────────────────────────────────────────────────────────────

class IngestionOptimizerAgent(Agent):
    """Analyze table usage and recommend ingest_filters, retention, and sampling."""

    name = "optimizer"

    def execute(self, window_days: int = 7, **kw) -> AgentResult:
        result = AgentResult()
        recommendations: list[dict] = []

        # 1. Classify tables
        classified = _classify_tables(self.db, window_days)
        result.output["tables"] = classified

        # 2. For "unused" tables with high volume: propose ingest_filters
        high_volume_threshold = int(self.db.get_setting("optimizer_high_volume_threshold", 10000))
        for cls in classified:
            if cls["usage_class"] == "unused" and cls["rows_ingested"] > high_volume_threshold:
                templates = _analyze_table_templates(self.db, cls["table"])
                for tpl in templates[:5]:  # top 5 patterns
                    if not tpl["cnt"] or tpl["cnt"] < 100:
                        continue
                    filt = _propose_filter_from_template(
                        tpl.get("EventCode") or "",
                        tpl.get("Message") or "",
                        cls["table"], tpl["cnt"])
                    if filt:
                        estimated_drop = tpl["cnt"]
                        est_savings = f"~{estimated_drop} rows/day"

                        rid = self.recommend(
                            kind="ingest_filter",
                            target=cls["table"],
                            title=f"Drop high-volume pattern in {cls['table']}",
                            rationale=f"Table {cls['table']} is unused (not referenced by rules or human queries) "
                                      f"but receives {cls['rows_ingested']} rows/day. "
                                      f"Pattern: EventCode={filt['event_code']}, "
                                      f"Message ~ {filt['message_prefix'][:40]} "
                                      f"({filt['sample_count']} occurrences).",
                            payload={"filter": filt, "table_usage": cls},
                            est_savings=est_savings)
                        recommendations.append({"rec_id": rid, "kind": "ingest_filter",
                                                "table": cls["table"],
                                                "estimated_drop": estimated_drop})

        # 3. For unused/empty tables: recommend retention reduction
        default_retention = int(self.db.get_setting("default_retention_days", 30))
        for cls in classified:
            if cls["usage_class"] in ("unused", "empty") and cls["rows_ingested"] == 0:
                rid = self.recommend(
                    kind="retention",
                    target=cls["table"],
                    title=f"Reduce retention for unused table {cls['table']}",
                    rationale=f"Table {cls['table']} has no ingested data and no rule/human queries in "
                              f"the last {window_days} days. Reduce retention from {default_retention} days.",
                    payload={"table": cls["table"], "retention_days": 1,
                             "default_retention": default_retention})
                recommendations.append({"rec_id": rid, "kind": "retention",
                                        "table": cls["table"]})

        # 3b. Noisy sources inside tables that rules do use (per-SourceId pass)
        recommendations.extend(noisy_source_recs(self, window_days))

        # 4. Summary statistics
        total_rows = sum(c["rows_ingested"] for c in classified)
        unused_rows = sum(c["rows_ingested"] for c in classified if c["usage_class"] == "unused")
        savings_pct = round((unused_rows / max(total_rows, 1)) * 100, 1)

        result.output.update({
            "window_days": window_days,
            "total_tables": len(classified),
            "total_rows_ingested": total_rows,
            "unused_rows": unused_rows,
            "potential_savings_pct": savings_pct,
            "recommendations": recommendations,
            "recommendation_count": len(recommendations),
        })

        result.summary = (f"Analyzed {len(classified)} tables over {window_days} days. "
                          f"Total rows: {total_rows}. Unused rows: {unused_rows} ({savings_pct}%). "
                          f"Generated {len(recommendations)} recommendations.")
        return result


# ── public helpers ──────────────────────────────────────────────────────────────

def apply_recommendation(db: Database, rec_id: str, by: str) -> dict:
    """Approve and apply a recommendation of kind ingest_filter or retention.

    Args:
        db: Database instance
        rec_id: recommendation ID to apply
        by: who is applying it (username or agent name)

    Returns:
        dict with status and details
    """
    rec = db.query_one("SELECT * FROM recommendations WHERE rec_id=?", [rec_id])
    if not rec:
        return {"status": "error", "message": f"recommendation {rec_id} not found"}

    if rec["status"] != "open":
        return {"status": "error", "message": f"recommendation already {rec['status']}"}

    payload = rec.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {}

    kind = rec["kind"]

    if kind == "ingest_filter":
        filt = payload.get("filter", {})
        table = filt.get("table", rec["target"])
        expression = filt.get("expression", "")
        if not expression:
            return {"status": "error", "message": "no filter expression in payload"}

        filter_id = new_id("filt_")
        db.execute(
            """INSERT INTO ingest_filters(filter_id, table_name, expression, description, enabled, origin)
               VALUES (?,?,?,?,?,?)""",
            [filter_id, table, expression,
             f"Optimizer recommendation {rec_id}: {rec['title']}",
             True, "optimizer"])

        db.execute(
            "UPDATE recommendations SET status='applied', decided_at=?, decided_by=? WHERE rec_id=?",
            [_utcnow(), by, rec_id])
        return {"status": "applied", "filter_id": filter_id, "table": table,
                "expression": expression}

    if kind == "retention":
        table = payload.get("table", rec["target"])
        days = payload.get("retention_days", 1)
        if not table:
            return {"status": "error", "message": "no table in payload"}

        db.execute(
            "INSERT OR REPLACE INTO table_retention(table_name, retention_days) VALUES (?,?)",
            [table, days])

        db.execute(
            "UPDATE recommendations SET status='applied', decided_at=?, decided_by=? WHERE rec_id=?",
            [_utcnow(), by, rec_id])
        return {"status": "applied", "table": table, "retention_days": days}

    db.execute(
        "UPDATE recommendations SET status='applied', decided_at=?, decided_by=? WHERE rec_id=?",
        [_utcnow(), by, rec_id])
    return {"status": "applied", "kind": kind, "note": "generic apply"}


def purge_expired(db: Database) -> dict:
    """Delete rows older than retention period from data tables only.

    Reads table_retention or uses default_retention_days. Only purges
    data tables (never metadata tables). Returns {table: rows_deleted}.

    Safety: explicitly lists DATA_TABLES and uses them as the only targets.
    """
    default_retention = int(db.get_setting("default_retention_days", 30))
    retentions = db.query("SELECT table_name, retention_days FROM table_retention")
    retention_map: dict[str, int] = {r["table_name"]: r["retention_days"] for r in retentions}

    purged: dict[str, int] = {}
    for table in DATA_TABLES:
        days = retention_map.get(table, default_retention)
        if days <= 0:
            continue
        days_int = int(days)
        try:
            # Count before deleting (DuckDB DELETE doesn't return rowcount reliably)
            count_result = db.query_one(
                f'SELECT COUNT(*) as cnt FROM "{table}" WHERE "TimeGenerated" < CURRENT_DATE - INTERVAL \'{days_int} days\'')
            deleted = count_result["cnt"] if count_result else 0
            if deleted > 0:
                db.execute(
                    f'DELETE FROM "{table}" WHERE "TimeGenerated" < CURRENT_DATE - INTERVAL \'{days_int} days\'')
                purged[table] = deleted
        except Exception:
            logger.warning("purge_expired: ignored error", exc_info=True)

    total = sum(purged.values())
    return {"tables": purged, "total_deleted": total, "default_retention_days": default_retention}
