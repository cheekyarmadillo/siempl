"""sentinel_to_rule: Microsoft Sentinel analytic rule YAML -> rule dict."""
from __future__ import annotations

import re

import yaml

from ..kql import KqlError, compile_kql
from ._convert_common import _triage_template
from ._convert_maps import SENTINEL_COLUMN_MAP, SENTINEL_TABLE_MAP
from ._core import UnsupportedRule


def sentinel_to_rule(yaml_text: str, source_ref: str = "") -> dict:
    """Convert an Azure-Sentinel detection YAML to a rule dict.

    Verifies the query compiles (or raises UnsupportedRule with reason).
    Sentinel KQL tables/columns are mapped to ours where feasible.
    """
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise UnsupportedRule(f"Invalid YAML: {e}") from e

    if not isinstance(doc, dict):
        raise UnsupportedRule("Sentinel YAML must be a mapping")

    name = doc.get("name", "Untitled Sentinel Rule")
    description = doc.get("description", "")
    severity = doc.get("severity", "Medium").capitalize()
    query = doc.get("query", "")
    tactics = doc.get("tactics", []) or []
    techniques = doc.get("relevantTechniques", []) or []

    if not query:
        raise UnsupportedRule("Sentinel rule has no 'query' field")

    # Map the query to our tables/columns
    mapped, tables, unmapped_reason = _map_sentinel_query(query)

    if unmapped_reason:
        raise UnsupportedRule(
            f"Sentinel rule '{name}' uses unsupported features: {unmapped_reason}")

    # Verify the query compiles
    try:
        compile_kql(mapped)
    except KqlError as e:
        raise UnsupportedRule(f"Sentinel rule '{name}' KQL does not compile: {e}") from e
    except Exception as e:
        raise UnsupportedRule(f"Sentinel rule '{name}' KQL compile error: {e}") from e

    # Normalize severity
    sev = severity.lower()
    if sev not in ("informational", "low", "medium", "high", "critical"):
        sev = "medium"

    # MITRE
    mitre_tactics = [t.lower().replace(" ", "_") for t in tactics]
    mitre_techniques = [t.upper() for t in techniques]

    # Entity mappings: guess from the Sentinel entity_mappings if present
    entity_mappings = _sentinel_entity_mappings(doc.get("entityMappings", []))

    # Triage
    triage = _triage_template(name, tables[0] if tables else "GenericEvents")

    return {
        "name": name,
        "description": description.strip(),
        "triage_steps": triage,
        "severity": sev,
        "query": mapped,
        "tables": tables,
        "mitre_tactics": mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "entity_mappings": entity_mappings,
        "origin": "sentinel",
        "source_ref": source_ref,
        "source_content": yaml_text,
    }


_STRING_LITERAL = r"'(?:[^'\\]|\\.)*'" + "|" + r'"(?:[^"\\]|\\.)*"'
_COLUMN_RE = re.compile(
    r"(" + _STRING_LITERAL + r")|\b("
    + "|".join(re.escape(c) for c in sorted(SENTINEL_COLUMN_MAP, key=lambda x: -len(x)))
    + r")\b",
    re.IGNORECASE,
)
_COLUMN_MAP_CI = {k.lower(): v for k, v in SENTINEL_COLUMN_MAP.items()}


def _map_columns(query: str) -> str:
    """Rename Sentinel columns to ours outside string literals."""
    def repl(m: re.Match) -> str:
        if m.group(1) is not None:
            return m.group(1)
        return _COLUMN_MAP_CI[m.group(2).lower()]
    return _COLUMN_RE.sub(repl, query)


# Sentinel entityType -> our entity type (see schema.ENTITY_TYPES). Types we
# cannot store (Url, AzureResource, ...) are skipped rather than failing at alert time.
_SENTINEL_ENTITY_TYPE_MAP = {
    "account": "user",
    "host": "host",
    "ip": "ip",
    "process": "process",
    "filehash": "file_hash",
    "dnsresolution": "domain",
}


def _map_sentinel_query(query: str) -> tuple[str, list[str], str | None]:
    """Map Sentinel KQL tables/columns to ours.

    Returns (mapped_query, tables, unmapped_reason).
    unmapped_reason is None on success.
    """
    # Find table names in the query and map them
    mapped = query
    tables = []

    # Map tables
    for sentinel_table, our_table in SENTINEL_TABLE_MAP.items():
        # Match as a word boundary after FROM/JOIN
        pattern = re.compile(r'\b' + re.escape(sentinel_table) + r'\b', re.IGNORECASE)
        if pattern.search(mapped):
            tables.append(our_table)
            mapped = pattern.sub(our_table, mapped)

    if not tables:
        tables = ["GenericEvents"]

    # Map columns in one pass, leaving string literals alone and emitting bare
    # identifiers (a double-quoted token would be a string literal in KQL).
    mapped = _map_columns(mapped)

    return mapped, list(set(tables)), None


def _sentinel_entity_mappings(raw_mappings: list) -> list[dict]:
    """Convert Sentinel entityMappings to our format."""
    result = []
    for m in (raw_mappings or []):
        etype = _SENTINEL_ENTITY_TYPE_MAP.get((m.get("entityType") or "").lower())
        field = m.get("fieldMappings", [{}])[0].get("columnName", "")
        if etype and field:
            col = SENTINEL_COLUMN_MAP.get(field, field)
            result.append({"entity_type": etype, "column": col})
    return result
