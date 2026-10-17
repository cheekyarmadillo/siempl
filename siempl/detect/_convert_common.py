"""Rule-dict helpers shared by the Sigma and Sentinel converters."""
from __future__ import annotations


def _normalize_timeframe(tf) -> str:
    """Normalize a Sigma timeframe like '5m' or '30s' to KQL ago format."""
    if isinstance(tf, str):
        return tf
    return "5m"


def _triage_template(title: str, table: str) -> str:
    """Generate basic triage steps for an imported rule."""
    return (
        f"1. Review the alert evidence rows from `{table}`.\n"
        f"2. Verify the process / user / IP context:\n"
        f"   - Is the user an administrator performing maintenance?\n"
        f"   - Is the IP internal and expected?\n"
        f"   - Is the process a known/trusted tool?\n"
        f"3. Run: `{table} | where ...` to get more context around the event time.\n"
        f"4. Check related entities (Users, Hosts, IPs) for other anomalous activity.\n"
        f"5. If benign, close as false_positive. If suspicious, escalate.\n"
        f"6. Document the verdict and any tuning needed."
    )


def _build_entity_mappings(table: str) -> list[dict]:
    """Build default entity mappings for a table based on ENTITY_COLUMNS."""
    from ..schema import ENTITY_COLUMNS, table_columns
    mappings = []
    seen = set()
    for col_name, _, _ in table_columns(table):
        if col_name in ENTITY_COLUMNS and col_name not in seen:
            mappings.append({"entity_type": ENTITY_COLUMNS[col_name], "column": col_name})
            seen.add(col_name)
    return mappings
