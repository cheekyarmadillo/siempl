"""Per-source noise detection for IngestionOptimizerAgent.

The table-level pass in optimizer.py cannot see a chatty source inside a table that
rules DO use. This module groups each table's rows by SourceId and flags a source when:
  - it is high-volume (rows >= min_rows AND (share >= min_share OR rows >= BIG_SOURCE_ROWS)),
  - no alert evidence mentions its SourceId, and
  - its top templates (EventCode + message with digit runs collapsed) cover >= 60% of its rows.

A flagged source gets an ingest_filter recommendation whose expression is scoped to that
SourceId and to the literal message prefix shared by the template.

Public:
  noisy_source_findings(db, window_days, min_rows, min_share) -> list[dict]
  noisy_source_recs(agent, window_days) -> list[dict]   (called from IngestionOptimizerAgent)
"""
from __future__ import annotations

from ..db import Database
from ..schema import COMMON_COLUMNS, DATA_TABLES

TEMPLATE_COVERAGE = 0.6
BIG_SOURCE_ROWS = 5000
TOP_TEMPLATES = 3
MIN_PREFIX_CHARS = 8
# Tokens the tiny ingest matcher (ingest._tiny_filter_match) cannot round-trip inside a
# quoted literal; any text containing them is never turned into a filter expression.
_UNSAFE_TOKENS = ('"', "\\", "\n", "\r", "==", " and ", "contains")


def _window(window_days: int) -> str:
    return f"TimeGenerated >= CURRENT_DATE - INTERVAL '{int(window_days)} days'"


def _has_source_column(table: str) -> bool:
    return any(c[0] == "SourceId" for c in COMMON_COLUMNS + DATA_TABLES[table]["columns"])


def _safe_text(text: str) -> bool:
    return not any(tok in text for tok in _UNSAFE_TOKENS)


def _literal_prefix(template: str) -> str:
    """Text before the first collapsed digit run; every raw row in the group starts with it."""
    head = template.split("#", 1)[0] if "#" in template else template
    return head.strip()


def _source_counts(db: Database, table: str, window_days: int) -> tuple[int, list[dict]]:
    rows = db.query(
        f'SELECT "SourceId" AS source_id, COUNT(*) AS rows FROM "{table}" '
        f"WHERE {_window(window_days)} GROUP BY 1")
    return sum(r["rows"] for r in rows), rows


def _top_templates(db: Database, table: str, source_id: str, window_days: int) -> list[dict]:
    rows = db.query(
        f"""SELECT COALESCE("EventCode", '') AS event_code,
                  regexp_replace(LEFT(COALESCE("Message", ''), 80), '[0-9]+', '#', 'g') AS tpl,
                  COUNT(*) AS cnt
           FROM "{table}"
           WHERE "SourceId" = ? AND {_window(window_days)}
           GROUP BY 1, 2 ORDER BY cnt DESC LIMIT {TOP_TEMPLATES}""",
        [source_id])
    return [{"event_code": r["event_code"], "message_prefix": _literal_prefix(r["tpl"]),
             "count": r["cnt"]} for r in rows]


def _alert_refs(db: Database, source_id: str) -> int:
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM alerts WHERE strpos(CAST(evidence AS VARCHAR), ?) > 0",
        [source_id])
    return int(row["n"]) if row else 0


def _filter_for(table: str, source_id: str, templates: list[dict]) -> dict | None:
    """First usable template becomes a filter; reuses optimizer's escaping and shape."""
    from .optimizer import _propose_filter_from_template  # local: optimizer imports this module
    for t in templates:
        prefix, code = t["message_prefix"], t["event_code"]
        if len(prefix) < MIN_PREFIX_CHARS or not _safe_text(prefix) or not _safe_text(code):
            continue
        filt = _propose_filter_from_template(code, prefix, table, t["count"])
        if filt:
            filt["expression"] = f'SourceId == "{source_id}" and {filt["expression"]}'
            return filt
    return None


def _is_noisy(source: dict, table_rows: int, min_rows: int, min_share: float) -> bool:
    rows = source["rows"]
    if rows < min_rows:
        return False
    return rows / max(table_rows, 1) >= min_share or rows >= BIG_SOURCE_ROWS


def _finding(db: Database, table: str, source: dict, table_rows: int, window_days: int) -> dict | None:
    sid = source["source_id"]
    if not sid or not _safe_text(sid) or _alert_refs(db, sid):
        return None
    templates = _top_templates(db, table, sid, window_days)
    if sum(t["count"] for t in templates) < TEMPLATE_COVERAGE * source["rows"]:
        return None
    filt = _filter_for(table, sid, templates)
    if filt is None:
        return None
    return {"table": table, "source_id": sid, "rows": source["rows"],
            "share": round(source["rows"] / max(table_rows, 1), 3), "templates": templates,
            "filter": filt, "est_savings": f"~{source['rows']} rows per {window_days}d"}


def noisy_source_findings(db: Database, window_days: int = 7, min_rows: int = 1000,
                          min_share: float = 0.2) -> list[dict]:
    """Noisy (table, SourceId) pairs with a ready-to-use filter; see the module docstring for the rule."""
    out: list[dict] = []
    for table in DATA_TABLES:
        if not _has_source_column(table):
            continue
        table_rows, sources = _source_counts(db, table, window_days)
        for source in sources:
            if _is_noisy(source, table_rows, min_rows, min_share):
                finding = _finding(db, table, source, table_rows, window_days)
                if finding:
                    out.append(finding)
    return out


def _already_open(db: Database, table: str, prefix: str) -> bool:
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM recommendations WHERE kind='ingest_filter' AND status='open' "
        "AND target=? AND strpos(CAST(payload AS VARCHAR), ?) > 0", [table, prefix[:40]])
    return bool(row and row["n"])


def noisy_source_recs(agent, window_days: int = 7) -> list[dict]:
    """Create one ingest_filter recommendation per noisy source (deduped); returns summary dicts."""
    made: list[dict] = []
    for f in noisy_source_findings(agent.db, window_days):
        filt = f["filter"]
        if _already_open(agent.db, f["table"], filt["message_prefix"]):
            continue
        rid = agent.recommend(
            kind="ingest_filter", target=f["table"],
            title=f"Drop noisy source {f['source_id']} pattern in {f['table']}",
            rationale=(f"Source {f['source_id']} sent {f['rows']} rows ({f['share']:.0%} of {f['table']}) in "
                       f"{window_days}d, its top templates cover most of them, and no alert references it. "
                       f"Pattern: {filt['message_prefix'][:40]}"),
            payload={"filter": filt, "source_id": f["source_id"], "rows": f["rows"]},
            est_savings=f["est_savings"])
        made.append({"rec_id": rid, "kind": "ingest_filter", "table": f["table"], "source_id": f["source_id"]})
    return made
