"""Detection engine (facade).

The implementation lives in the sibling _*.py modules; this module re-exports every name that used to be
defined here so existing imports keep working. Layout and rules: docs/DETECT.md.
"""
from __future__ import annotations

from ._alerts import (
    _extract_entities_from_rows,
    create_alert,
    set_verdict,
)
from ._convert_common import (
    _build_entity_mappings,
    _normalize_timeframe,
    _triage_template,
)
from ._convert_maps import (
    SENTINEL_COLUMN_MAP,
    SENTINEL_TABLE_MAP,
    SIGMA_FIELD_MAP,
    SIGMA_LOGSOURCE_TABLE,
    SIGMA_PRODUCT_TABLE,
)

# ruff: noqa: F401
from ._core import (
    UnsupportedRule,
    _escape_sql_str,
    _from_json,
    _json,
    _json_list,
)
from ._rule_store import (
    RuleStore,
)
from ._runner import (
    MAX_CONSECUTIVE_FAILURES,
    RuleRunner,
    start_scheduler,
)
from ._sentinel import (
    _map_sentinel_query,
    _sentinel_entity_mappings,
    sentinel_to_rule,
)
from ._sigma_kql import (
    _MODIFIER_LIST_TEMPLATES,
    _MODIFIER_SCALAR_TEMPLATES,
    _NUMERIC_COLS,
    _OF_PATTERN_RE,
    _SIGMA_IDENT_RE,
    _cidr_condition,
    _escape_kql_str,
    _expand_of_expression,
    _expand_pattern,
    _field_eq,
    _kql_value,
    _map_sigma_field,
    _modifier_condition,
    _modifier_to_kql,
    _plain_spec_to_kql,
    _replace_tokens,
    _resolve_sigma_table,
    _sigma_condition_to_kql,
    _sigma_selection_to_kql,
)
from ._sigma_rule import (
    _check_sigma_aggregation,
    _reject_trivial_condition,
    _sigma_to_rule_pysigma,
    sigma_to_rule,
)
