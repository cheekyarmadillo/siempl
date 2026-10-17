"""Internal helpers for discovery.py to keep module size under control."""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from .. import config as _config
from ..db import Database
from ..detect._run_rule import run_rule_query
from ..detect.engine import RuleStore
from ..schema import DATA_TABLES, ENTITY_COLUMNS, table_columns

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _count_events_per_table(db: Database, source_id: str) -> dict[str, int]:
    table_events: dict[str, int] = {}
    for table in DATA_TABLES:
        try:
            r = db.query_one(f'SELECT COUNT(*) as cnt FROM "{table}" WHERE "SourceId"=?', [source_id])
            if r and r["cnt"]:
                table_events[table] = r["cnt"]
        except Exception:
            logger.debug("_validate_source: ignored error", exc_info=True)
    return table_events


def _check_gaps(db: Database, source_id: str, table_events: dict[str, int]) -> list[dict]:
    findings: list[dict] = []
    for table, count in table_events.items():
        try:
            last = db.query_one(f'SELECT MAX("TimeGenerated") as ts FROM "{table}" WHERE "SourceId"=?', [source_id])
            if last and last["ts"]:
                gap = _utcnow() - last["ts"]
                if gap > timedelta(hours=1):
                    findings.append({
                        "level": "info" if gap < timedelta(hours=24) else "warning",
                        "table": table, "event_count": count,
                        "last_event_at": str(last["ts"]),
                        "gap_hours": round(gap.total_seconds() / 3600, 1),
                        "message": f"Last event {gap.total_seconds()/3600:.1f}h ago",
                        "recommendation": "Check source connectivity" if gap > timedelta(hours=24) else "",
                    })
        except Exception:
            logger.debug("_validate_source: ignored error", exc_info=True)
    return findings


def _check_null_rates(db: Database, source_id: str, most_events_table: str | None) -> list[dict]:
    findings: list[dict] = []
    if not most_events_table:
        return findings
    cols = [c[0] for c in table_columns(most_events_table)]
    for col in ("HostName", "UserName", "SrcIp", "EventCode", "Message"):
        if col not in cols:
            continue
        try:
            r = db.query_one(
                f'SELECT COUNT(*) as total, '
                f'COUNT(CASE WHEN "{col}" IS NULL OR "{col}" = \'\' THEN 1 END) as nulls '
                f'FROM "{most_events_table}" WHERE "SourceId"=?',
                [source_id])
            if r and r["total"] > 0:
                null_pct = round(r["nulls"] / r["total"] * 100, 1)
                if null_pct > 50:
                    findings.append({
                        "level": "warning", "table": most_events_table,
                        "column": col, "null_pct": null_pct,
                        "message": f"Column {col} is NULL/empty in {null_pct}% of rows",
                        "recommendation": "Check parser field mapping for this column",
                    })
        except Exception:
            logger.debug("_validate_source: ignored error", exc_info=True)
    return findings


def _check_entity_coverage(db: Database, source_id: str, most_events_table: str | None) -> list[dict]:
    findings: list[dict] = []
    if not most_events_table:
        return findings
    cols = [c[0] for c in table_columns(most_events_table)]
    entity_cols = {col: etype for col, etype in ENTITY_COLUMNS.items() if col in cols}
    for col, etype in entity_cols.items():
        try:
            r = db.query_one(
                f'SELECT COUNT(*) as total, '
                f'COUNT(CASE WHEN "{col}" IS NOT NULL AND "{col}" != \'\' THEN 1 END) as filled '
                f'FROM "{most_events_table}" WHERE "SourceId"=?',
                [source_id])
            if r and r["total"] > 0:
                fill_pct = round(r["filled"] / r["total"] * 100, 1)
                if fill_pct < 10:
                    findings.append({
                        "level": "info", "table": most_events_table,
                        "column": col, "entity_type": etype,
                        "fill_pct": fill_pct,
                        "message": f"Entity column {col} ({etype}) only filled in {fill_pct}% of rows",
                        "recommendation": "Check if parser maps source fields to entity columns",
                    })
        except Exception:
            logger.debug("_validate_source: ignored error", exc_info=True)
    return findings


def _determine_sourcetype(table_events: dict[str, int]) -> str:
    events_in_table = {t: c for t, c in table_events.items() if t != "GenericEvents" and c > 0}
    if events_in_table:
        return max(events_in_table, key=events_in_table.get)
    if "GenericEvents" in table_events and table_events["GenericEvents"] > 0:
        return "generic"
    return "unknown"


def _tables_with_data(db: Database) -> list[str]:
    tables_with_data: list[str] = []
    for table in DATA_TABLES:
        try:
            r = db.query_one(f'SELECT COUNT(*) as cnt FROM "{table}"', [])
            if r and r["cnt"] and r["cnt"] > 0:
                tables_with_data.append(table)
        except Exception:
            logger.debug("_fetch_and_import_rules: ignored error", exc_info=True)
    return tables_with_data


def _fetch_sigma_rules(db: Database, tables_with_data: list[str], http_client, results: dict) -> list[dict]:
    SIGMA_DIRS = {"ProcessEvents": "process_creation", "NetworkEvents": "network_connection",
                  "FileEvents": "file/file_event"}
    all_rules: list[dict] = []
    try:
        # Lazy import on purpose: tests (and callers) monkeypatch detect.importer.fetch_sigma.
        from ..detect import importer as _importer
        client = http_client if callable(http_client) else None
        cache_dir = str(_config.home() / "rules_cache")
        for tbl in tables_with_data:
            sub = SIGMA_DIRS.get(tbl)
            if not sub:
                continue
            try:
                got = _importer.fetch_sigma(client=client, cache_dir=cache_dir, paths_or_query=sub, max_files=8)
                all_rules.extend(got)
                results.setdefault("fetched", {})[sub] = len(got)
            except Exception as e:
                results["errors"].append({"source": f"sigma:{sub}", "error": str(e)[:200]})
    except ImportError:
        results["errors"].append({"source": "fetch", "error": "importer unavailable"})
    if not any(t in SIGMA_DIRS for t in tables_with_data):
        results["reason"] = "No data in tables with a Sigma folder mapping (ProcessEvents, NetworkEvents, FileEvents)"
    return all_rules


def _validate_imported_rule(db: Database, rule: dict, existing_refs: set[str]) -> str | None:
    ref = rule.get("source_ref", "")
    if ref in existing_refs:
        return "duplicate source_ref"
    query = rule.get("query", "")
    lang = rule.get("query_lang") or "kql"
    if not query:
        return None
    try:
        qr = run_rule_query(db, query, rule_id="import_validation", limit=101, log=False,
                            query_lang=lang, lookback_minutes=60 * 24 * 365)
        rule["hits_in_data"] = len(qr.rows)
        if len(qr.rows) > 100:
            return f"too noisy ({len(qr.rows)}+ rows)"
    except Exception as e:
        return f"query error: {str(e)[:120]}"
    return None


def _import_or_propose_rule(db: Database, agent, rule: dict, results: dict) -> None:
    ref = rule.get("source_ref", "")
    if agent is not None and agent.dry_run:
        payload = {k: rule.get(k) for k in ("name", "description", "triage_steps", "severity", "query", "query_lang",
                                            "tables", "mitre_tactics", "mitre_techniques", "entity_mappings",
                                            "source_ref", "source_content")}
        payload.update({"origin": rule.get("origin") or ("sigma" if "sigma" in ref else "sentinel"), "enabled": False})
        agent.recommend("new_rule", rule.get("name") or "imported rule", f"Import rule: {rule.get('name')}",
                        f"Imported from {ref}; {rule.get('hits_in_data', 0)} hit(s) in current data.", payload=payload)
        results["proposed"] = results.get("proposed", 0) + 1
        results["imported_rules"].append({"rule_id": None, "name": rule.get("name"), "proposed": True,
                                          "hits": rule.get("hits_in_data", 0)})
        return
    rule_id = RuleStore(db).create({**rule, "enabled": False,
                                    "origin": rule.get("origin") or ("sigma" if "sigma" in ref else "sentinel")})
    results["imported"] += 1
    results["imported_rules"].append({"rule_id": rule_id, "name": rule.get("name"),
                                      "hits": rule.get("hits_in_data", 0)})
