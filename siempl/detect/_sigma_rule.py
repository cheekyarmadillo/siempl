"""sigma_to_rule: Sigma YAML -> rule dict (pySigma first, hand translator as fallback)."""
from __future__ import annotations

import re

import yaml

from ..kql import KqlError, compile_kql
from ._convert_common import _build_entity_mappings, _normalize_timeframe, _triage_template
from ._core import UnsupportedRule
from ._sigma_kql import _map_sigma_field, _resolve_sigma_table, _sigma_condition_to_kql, _sigma_selection_to_kql


def _sigma_to_rule_pysigma(doc: dict, yaml_text: str, source_ref: str) -> dict:
    """Sigma -> rule dict whose executable query is DuckDB SQL (query_lang='sql')."""
    from .sigma_backend import sigma_doc_to_sql
    table, sql = sigma_doc_to_sql(doc)
    title = doc.get("title", "Untitled Sigma Rule")
    description = doc.get("description", "") or ""
    falsepositives = doc.get("falsepositives", []) or []
    full_desc = description
    if falsepositives:
        full_desc = f"{description}\n\nKnown false positives: " + "; ".join(str(f) for f in falsepositives)
    tactics, techniques = [], []
    for tag in (doc.get("tags") or []):
        if isinstance(tag, str) and tag.startswith("attack."):
            rest = tag[7:]
            (techniques if rest.startswith("t") else tactics).append(rest.upper() if rest.startswith("t") else rest)
    level = str(doc.get("level", "medium")).lower()
    return {
        "name": title, "description": full_desc.strip(),
        "triage_steps": _triage_template(title, table),
        "severity": level if level in ("informational", "low", "medium", "high", "critical") else "medium",
        "query": sql, "query_lang": "sql", "tables": [table],
        "mitre_tactics": tactics, "mitre_techniques": techniques,
        "entity_mappings": _build_entity_mappings(table),
        "origin": "sigma", "source_ref": source_ref, "source_content": yaml_text,
    }


def _reject_trivial_condition(cond: str) -> None:
    """Never import a rule whose condition is empty/'true' (it would match every row)."""
    stripped = re.sub(r"[\s()]", "", cond or "").lower()
    if stripped in ("", "true", "trueandtrue", "trueortrue"):
        raise UnsupportedRule("Sigma condition translated to a match-everything expression; refusing to import")


def sigma_to_rule(yaml_text: str, source_ref: str = "", backend: str = "auto") -> dict:
    """Convert Sigma YAML to a rule dict ready for RuleStore.create().

    backend: "auto" (pySigma SQL first, KQL translator as fallback) or "kql" (force the KQL translator).

    Raises UnsupportedRule if the Sigma cannot be converted.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise UnsupportedRule(f"Invalid YAML: {e}") from e

    if not isinstance(doc, dict):
        raise UnsupportedRule("Sigma YAML must be a mapping")

    title = doc.get("title", "Untitled Sigma Rule")
    description = doc.get("description", "")
    level = doc.get("level", "medium")
    logsource = doc.get("logsource", {})
    detection = doc.get("detection", {})
    tags = doc.get("tags", [])
    falsepositives = doc.get("falsepositives", [])

    # Resolve table
    table = _resolve_sigma_table(logsource)

    # Build KQL condition
    condition_str = detection.get("condition", "")
    if not condition_str:
        raise UnsupportedRule("Sigma rule has no 'condition' field")

    selections = {k: v for k, v in detection.items() if k != "condition" and k != "timeframe"}
    if not selections:
        raise UnsupportedRule("Sigma rule has no detection selections")

    # Primary path: pySigma -> DuckDB SQL (rules without aggregation).
    if backend != "kql" and not _check_sigma_aggregation(detection, table):
        try:
            return _sigma_to_rule_pysigma(doc, yaml_text, source_ref)
        except UnsupportedRule:
            pass   # fall back to the KQL translator below (which refuses trivially-true conditions)

    from .sigma_backend import _check_fields
    _check_fields(detection, table)   # refuse rules needing columns this table does not have
    kql_condition = _sigma_condition_to_kql(condition_str, selections, table)
    _reject_trivial_condition(kql_condition)

    # Check for aggregation: `count() by X > N`
    aggregation_expr = _check_sigma_aggregation(detection, table)

    if aggregation_expr:
        query = aggregation_expr
    else:
        # Build KQL pipe query
        lookback = doc.get("detection", {}).get("timeframe", "5m")
        query = (
            f'{table} | where TimeGenerated > ago({_normalize_timeframe(lookback)}) '
            f'and ({kql_condition})'
        )



    # MITRE
    mitre_tactics = []
    mitre_techniques = []
    for tag in (tags or []):
        if isinstance(tag, str) and tag.startswith("attack."):
            rest = tag[7:]
            if rest.startswith("t"):
                mitre_techniques.append(rest.upper())
            else:
                mitre_tactics.append(rest)

    # Description
    full_desc = description
    if falsepositives:
        fp_list = "; ".join(str(f) for f in falsepositives)
        full_desc = f"{description}\n\nKnown false positives: {fp_list}"

    # Triage steps
    triage = _triage_template(title, table)

    # Entity mappings
    entity_mappings = _build_entity_mappings(table)

    # Severity mapping
    sev_map = {
        "informational": "informational", "low": "low", "medium": "medium",
        "high": "high", "critical": "critical",
    }

    # Verify KQL compiles
    try:
        compile_kql(query)
    except KqlError as e:
        raise UnsupportedRule(f"Sigma rule KQL does not compile: {e}") from e
    except Exception as e:
        raise UnsupportedRule(f"Sigma rule KQL compile error: {e}") from e

    return {
        "name": title,
        "description": full_desc.strip(),
        "triage_steps": triage,
        "severity": sev_map.get(level, "medium"),
        "query": query,
        "tables": [table],
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "entity_mappings": entity_mappings,
        "origin": "sigma",
        "source_ref": source_ref,
        "source_content": yaml_text,
        "query_lang": "kql",
    }


def _check_sigma_aggregation(detection: dict, table: str) -> str | None:
    """Check if the Sigma rule uses aggregation (count() by field > N).

    Returns a canonical KQL query string (summarize ... by ...) or None.
    """
    timefield = detection.get("timeframe", "5m")
    lookback = _normalize_timeframe(timefield)

    def _group_cols(sel: dict, count_field: str) -> list[str]:
        """Group by the base field of every non-count spec in the selection."""
        cols = []
        for f in sel:
            if f == count_field:
                continue
            base, _, mod = f.rpartition('|')
            if mod == 'count':
                continue
            col = _map_sigma_field(base if mod else f)
            if col not in cols:
                cols.append(col)
        return cols

    def _build(sel: dict, count_field: str, count_spec) -> str:
        cols = _group_cols(sel, count_field)
        op = ">=" if str(count_spec).lstrip().startswith(">=") else ">"
        try:
            threshold = int(str(count_spec).lstrip(">= "))
        except ValueError:
            threshold = 1
        # Row filter: the selection itself (its |count key is skipped there).
        row_filter = _sigma_selection_to_kql(sel, table)
        by_clause = f" by {', '.join(cols)}" if cols else ""
        return (
            f"{table} | where TimeGenerated > ago({lookback}) "
            f"and ({row_filter}) "
            f"| summarize cnt=count(){by_clause} "
            f"| where cnt {op} {threshold}"
        )

    # Check for `Field|count` modifiers in selections that indicate aggregation.
    # The |count modifier can appear either in the field KEY (e.g. "CommandLine|count")
    # or as a key inside the spec VALUE dict (e.g. {"|count": ">= 5"}).
    for key, sel in detection.items():
        if key == "condition" or key == "timeframe":
            continue
        if not isinstance(sel, dict):
            continue
        for field, spec in sel.items():
            # Check for |count in the field key
            if '|' in field:
                _, _, modifier = field.rpartition('|')
                if modifier == 'count':
                    return _build(sel, field, spec)
            # Check for |count in the value dict
            if isinstance(spec, dict) and "|count" in spec:
                return _build(sel, field, spec["|count"])
    return None
