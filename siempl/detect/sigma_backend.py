"""Sigma -> DuckDB SQL via pySigma (primary Sigma path).

Pipeline per target table:
  * FieldMapping: SIGMA_FIELD_MAP entries whose target column exists in the table are
    renamed to that column.  A known Sigma field whose column does NOT exist in the target
    table raises UnsupportedRule before conversion (no silent non-match).
  * Unknown Sigma fields (not in SIGMA_FIELD_MAP) map to ``Extra->>'<field>'`` (the JSON
    `Extra` column that parsers fill with unmapped source fields).  This never raises a
    binder error.
  * Table: chosen by logsource category (see TABLE_FOR_CATEGORY / SIGMA_LOGSOURCE_TABLE).
Dialect (sqlite backend -> DuckDB shims):
  * REGEXP -> regexp_matches(field, 'pattern')
  * LIKE   -> ILIKE (Sigma default matching is case-insensitive); ESCAPE '\\' kept.
  * GLOB (|cased) is valid DuckDB and is left as is.

Output: a plain ``SELECT * FROM "<Table>" WHERE <cond>`` string.  No time window: the
rule runner applies ``TimeGenerated > now - lookback`` around it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation, SetStateTransformation

from .. import schema
from .engine import SIGMA_FIELD_MAP, SIGMA_LOGSOURCE_TABLE, UnsupportedRule

EXTRA_PREFIX = "__extra__:"
_EXTRA_KEY_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")

# Sigma logsource category -> our table.  Categories not listed fall back to SIGMA_LOGSOURCE_TABLE.
TABLE_FOR_CATEGORY: dict[str, str] = {
    "process_creation": "ProcessEvents",
    "file_event": "FileEvents",
    "network_connection": "NetworkEvents",
    "dns_query": "NetworkEvents",
}


def table_for_logsource(logsource: dict) -> str:
    cat = str((logsource or {}).get("category") or "").lower()
    if cat in TABLE_FOR_CATEGORY:
        return TABLE_FOR_CATEGORY[cat]
    if cat in SIGMA_LOGSOURCE_TABLE:
        return SIGMA_LOGSOURCE_TABLE[cat]
    raise UnsupportedRule(f"pySigma path: no table for logsource category '{cat or '<none>'}'")


def _table_columns(table: str) -> set[str]:
    return {name for name, _, _ in schema.table_columns(table)}


def _extra_field(key: str) -> str:
    return EXTRA_PREFIX + key


@dataclass
class ExtraFallbackTransformation(FieldMappingTransformation):
    """Field mapping with a dynamic fallback: unknown fields -> Extra->>'field'."""

    mapping: dict = field(default_factory=dict)

    def apply_field_name(self, fld: str | None):
        if fld is None:
            return None
        if fld in self.mapping:
            return self.mapping[fld]
        return _extra_field(fld)


class SqlBackend(sqliteBackend):
    """sqlite backend with DuckDB dialect shims and Extra fallback quoting."""

    identifier = "siempl-duckdb"
    name = "siempl DuckDB (sqlite-derived)"

    startswith_expression = "{field} ILIKE '{value}%' ESCAPE '\\'"
    endswith_expression = "{field} ILIKE '%{value}' ESCAPE '\\'"
    contains_expression = "{field} ILIKE '%{value}%' ESCAPE '\\'"
    wildcard_match_expression = "{field} ILIKE '{value}' ESCAPE '\\'"
    wildcard_match_str_expression = "{field} ILIKE '{value}' ESCAPE '\\'"
    re_expression = "regexp_matches({field}, '{regex}')"
    null_safe_expression = "COALESCE({expr}, false)"   # DuckDB is strictly typed (sqlite uses 0)

    def escape_and_quote_field(self, fld):
        if fld.startswith(EXTRA_PREFIX):
            key = fld[len(EXTRA_PREFIX):]
            if not _EXTRA_KEY_RE.match(key):
                raise UnsupportedRule(f"Sigma field '{key}' cannot be used as an Extra key")
            return f"(Extra->>'{key}')"   # parens: ->> binds looser than = / ILIKE in DuckDB
        return super().escape_and_quote_field(fld)


@lru_cache(maxsize=8)
def _backend_for_table(table: str) -> SqlBackend:
    cols = _table_columns(table)
    mapping = {sig: col for sig, col in SIGMA_FIELD_MAP.items() if col in cols}
    items = [
        ProcessingItem(identifier="siempl_fields",
                       transformation=ExtraFallbackTransformation(mapping=mapping)),
        ProcessingItem(identifier="siempl_table",
                       transformation=SetStateTransformation("table", table)),
    ]
    pipe = ProcessingPipeline(name=f"siempl-{table}", priority=10, items=items)
    return SqlBackend(processing_pipeline=pipe)


def _base_fields(detection: dict) -> list[str]:
    """All Sigma field names used in selections (modifiers stripped).

    A selection is a field->value map or a LIST of such maps (alternatives) or a list of keyword
    strings (no field). Selection names themselves are not fields."""
    out: list[str] = []
    for name, sel in detection.items():
        if name in ("condition", "timeframe"):
            continue
        maps = sel if isinstance(sel, list) else [sel]
        for m in maps:
            if isinstance(m, dict):
                out.extend(str(k).split("|")[0] for k in m)
    return out


def _check_fields(detection: dict, table: str) -> None:
    cols = _table_columns(table)
    for fld in set(_base_fields(detection)):
        if fld in SIGMA_FIELD_MAP:
            col = SIGMA_FIELD_MAP[fld]
            if col not in cols:
                raise UnsupportedRule(
                    f"Sigma field '{fld}' maps to column '{col}', which table {table} does not have")
        elif not _EXTRA_KEY_RE.match(fld):
            raise UnsupportedRule(f"Unmapped Sigma field '{fld}' is not usable as an Extra key")


_TRIVIAL_WHERE_RE = re.compile(r"\bWHERE\s*\(*\s*(true|1\s*=\s*1)?\s*\)*\s*$", re.IGNORECASE)


def sigma_doc_to_sql(doc: dict) -> tuple[str, str]:
    """Convert a parsed Sigma rule document. Returns (table, sql).

    Raises UnsupportedRule for anything pySigma cannot express or that would be trivially true.
    """
    if not isinstance(doc, dict):
        raise UnsupportedRule("Sigma YAML must be a mapping")
    detection = doc.get("detection") or {}
    if not isinstance(detection, dict) or not detection.get("condition"):
        raise UnsupportedRule("Sigma rule has no 'condition' field")
    table = table_for_logsource(doc.get("logsource") or {})
    _check_fields(detection, table)
    backend = _backend_for_table(table)
    # Clean copy for pySigma: drop non-selection metadata keys it does not need.
    clean_detection = {k: v for k, v in detection.items() if k != "timeframe"}
    clean_doc = {k: v for k, v in doc.items() if k in ("title", "id", "status", "logsource", "detection", "level")}
    clean_doc["detection"] = clean_detection
    try:
        collection = SigmaCollection.from_dicts([clean_doc])
        queries = backend.convert(collection)
    except UnsupportedRule:
        raise
    except Exception as e:  # pySigma parse/convert error: report, caller may fall back
        raise UnsupportedRule(f"pySigma: {type(e).__name__}: {str(e)[:160]}") from e
    if not queries:
        raise UnsupportedRule("pySigma produced no query")
    if len(queries) != 1:
        raise UnsupportedRule(f"pySigma produced {len(queries)} queries; expected 1")
    sql = str(queries[0]).strip().rstrip(";").strip()
    if "WHERE" not in sql.upper():
        raise UnsupportedRule("pySigma SQL has no WHERE clause (would match every row)")
    if _TRIVIAL_WHERE_RE.search(sql):
        raise UnsupportedRule("pySigma SQL condition is trivially true")
    if not sql.upper().startswith("SELECT"):
        raise UnsupportedRule("pySigma SQL is not a plain SELECT")
    return table, sql


def sigma_yaml_to_sql(yaml_text: str) -> tuple[str, str, dict]:
    """Parse YAML then convert. Returns (table, sql, parsed_doc)."""
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise UnsupportedRule(f"Invalid YAML: {e}") from e
    table, sql = sigma_doc_to_sql(doc)
    return table, sql, doc
