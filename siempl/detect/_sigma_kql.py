"""Sigma detection -> KQL condition translation (field mapping, modifiers, 'N of' expansion, condition parser)."""
from __future__ import annotations

import re

from ._convert_maps import SIGMA_FIELD_MAP, SIGMA_LOGSOURCE_TABLE, SIGMA_PRODUCT_TABLE
from ._core import UnsupportedRule, _escape_sql_str


def _resolve_sigma_table(logsource: dict) -> str:
    """Resolve Sigma logsource to our table name."""
    cat = (logsource.get("category") or "").lower()
    prod = (logsource.get("product") or "").lower()
    svc = (logsource.get("service") or "").lower()

    # Exact match first
    if cat in SIGMA_LOGSOURCE_TABLE:
        return SIGMA_LOGSOURCE_TABLE[cat]
    if svc and svc in SIGMA_LOGSOURCE_TABLE:
        return SIGMA_LOGSOURCE_TABLE[svc]
    if prod in SIGMA_PRODUCT_TABLE:
        return SIGMA_PRODUCT_TABLE[prod]
    # Fallback
    if "process" in cat or "process" in svc or "sysmon" in prod or "sysmon" in svc:
        return "ProcessEvents"
    if "network" in cat or "dns" in cat:
        return "NetworkEvents"
    if "auth" in cat:
        return "AuthEvents"
    if "file" in cat:
        return "FileEvents"
    if "web" in cat or "proxy" in cat:
        return "WebAccess"
    return "GenericEvents"


_SIGMA_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _map_sigma_field(field: str) -> str:
    """Map a Sigma field name to our column/expression.

    Known fields map to a real column.  Unknown fields fall back to dynamic
    access on the JSON `Extra` column: ``tostring(Extra.FieldName)`` (or
    ``tostring(Extra['field name'])`` when the name is not a valid KQL
    identifier).  Parsers stash unmapped source fields in `Extra`, so this
    lets real SigmaHQ rules import and run instead of being rejected.
    """
    # Strip any Sigma modifier suffix (|contains, |endswith, etc.)
    base_field = field.split('|')[0]
    if base_field in SIGMA_FIELD_MAP:
        return SIGMA_FIELD_MAP[base_field]
    if _SIGMA_IDENT_RE.match(base_field):
        return f"tostring(Extra.{base_field})"
    if "'" not in base_field:
        return f"tostring(Extra['{base_field}'])"
    raise UnsupportedRule(
        f"Unmapped Sigma field '{field}' — name not usable as an Extra key")


def _escape_kql_str(s: str) -> str:
    """Escape a string value for inclusion in a KQL double-quoted string."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


# Our INTEGER columns: Sigma values for these must be emitted unquoted,
# otherwise DuckDB compares INTEGER to VARCHAR and the rule silently
# matches nothing.
_NUMERIC_COLS = {
    "SrcPort", "DstPort", "ProcessId", "ParentProcessId", "StatusCode", "SeverityLevel", "Bytes", "BytesIn", "BytesOut",
}


def _kql_value(col: str, v) -> str:
    """Render a Sigma value as a KQL literal appropriate for *col*."""
    if col in _NUMERIC_COLS:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return str(int(v))
        if isinstance(v, str) and re.fullmatch(r"-?\d+", v.strip()):
            return v.strip()
    return f'"{_escape_kql_str(str(v))}"'


def _sigma_selection_to_kql(selection: dict, table: str) -> str:
    """Convert a Sigma selection map to KQL conditions."""
    if isinstance(selection, list):
        subs = [_sigma_selection_to_kql(s, table) for s in selection if isinstance(s, dict)]
        return "(" + " or ".join(subs) + ")" if subs else "true"
    parts = []
    for raw_key, spec in selection.items():
        if '|' in raw_key:
            field_name, _, modifier = raw_key.rpartition('|')
            col = _map_sigma_field(field_name)
            parts.append(_modifier_to_kql(col, modifier, spec))
        else:
            col = _map_sigma_field(raw_key)
            parts.append(_plain_spec_to_kql(col, spec))
    return " and ".join(parts) or "true"


def _modifier_to_kql(col: str, modifier: str, spec) -> str:
    """Single modifier branch for scalar/list spec."""
    if isinstance(spec, list):
        joiner, tmpl = _MODIFIER_LIST_TEMPLATES.get(modifier, (" or ", '{col} == "{val}"'))
        if tmpl is None:  # cidr
            return _cidr_condition(col, spec)
        if tmpl == "":   # count aggregation skipped
            return "true"
        sub = joiner.join(tmpl.format(col=col, val=_escape_kql_str(str(v))) for v in spec)
        return f"({sub})"
    if isinstance(spec, dict):
        return _modifier_condition(col, spec)
    # scalar with modifier
    val = _escape_kql_str(str(spec))
    tmpl = _MODIFIER_SCALAR_TEMPLATES.get(modifier)
    if tmpl is None:
        return f'{col} == "{val}"'
    if tmpl == "":
        return "true"
    if tmpl == "cidr":
        return _cidr_condition(col, spec)
    return tmpl.format(col=col, val=val)


def _plain_spec_to_kql(col: str, spec) -> str:
    """Plain field without modifier."""
    if isinstance(spec, dict):
        return _modifier_condition(col, spec)
    if isinstance(spec, list):
        vals = ", ".join(_kql_value(col, v) for v in spec)
        return f"{col} in ({vals})"
    return f"{col} == {_kql_value(col, spec)}"


_MODIFIER_LIST_TEMPLATES: dict[str, tuple[str, str | None]] = {
    "contains": (" or ", '{col} contains "{val}"'),
    "startswith": (" or ", '{col} startswith "{val}"'),
    "endswith": (" or ", '{col} endswith "{val}"'),
    "re": (" or ", '{col} matches regex "{val}"'),
    "all": (" and ", '{col} contains "{val}"'),
    "cidr": ("", None),
    "count": ("", ""),
}


_MODIFIER_SCALAR_TEMPLATES: dict[str, str] = {
    "contains": '{col} contains "{val}"',
    "startswith": '{col} startswith "{val}"',
    "endswith": '{col} endswith "{val}"',
    "re": '{col} matches regex "{val}"',
    "all": '{col} contains "{val}"',
    "cidr": "cidr",
    "count": "",
}


def _modifier_condition(col: str, spec: dict) -> str:
    """Convert a Sigma modifier dict to a KQL condition."""
    # If spec has modifier keys
    if any(k.startswith("|") for k in spec):
        # Multiple modifiers on one field are ANDed
        sub = []
        for mod, val in spec.items():
            if mod == "|contains":
                # contains is case-insensitive by default in DuckDB
                for v in ([val] if not isinstance(val, list) else val):
                    sub.append(f'{col} contains "{_escape_kql_str(str(v))}"')
            elif mod == "|startswith":
                for v in ([val] if not isinstance(val, list) else val):
                    sub.append(f'{col} startswith "{_escape_kql_str(str(v))}"')
            elif mod == "|endswith":
                for v in ([val] if not isinstance(val, list) else val):
                    sub.append(f'{col} endswith "{_escape_kql_str(str(v))}"')
            elif mod == "|re":
                v = val if not isinstance(val, list) else val[0]
                sub.append(f"regexp_matches({col}, '{_escape_sql_str(str(v))}')")
            elif mod == "|all":
                for v in ([val] if not isinstance(val, list) else val):
                    sub.append(f'{col} contains "{_escape_kql_str(str(v))}"')
            elif mod == "|cidr":
                # CIDR matching: use DuckDB IP functions where available,
                # fall back to string prefix matching for simple cases
                sub.append(_cidr_condition(col, val))
        return " and ".join(f"({s})" for s in sub) if sub else "true"
    # Plain dict: each key is another nested condition
    parts = [_field_eq(col, k, v) for k, v in spec.items()]
    return " and ".join(parts) or "true"


def _field_eq(col: str, op: str, val) -> str:
    v = _escape_kql_str(str(val))
    if op == "contains":
        return f'{col} contains "{v}"'
    if op == "startswith":
        return f'{col} startswith "{v}"'
    if op == "endswith":
        return f'{col} endswith "{v}"'
    if op == "re":
        return f'{col} matches regex "{v}"'
    return f'{col} == "{v}"'


def _cidr_condition(col: str, val) -> str:
    """Sigma |cidr modifier -> ipv4_is_in_range(column, cidr)."""
    if isinstance(val, list):
        parts = [f'ipv4_is_in_range({col}, "{_escape_kql_str(str(v))}")' for v in val]
        return "(" + " or ".join(parts) + ")"
    return f'ipv4_is_in_range({col}, "{_escape_kql_str(str(val))}")'


def _sigma_condition_to_kql(cond: str, selections: dict[str, dict],
                            table: str) -> str:
    """Convert a Sigma condition expression to KQL.

    condition is a string like:
      'selection1 and selection2'
      'selection1 and not selection2'
      'selection1 or selection2'
      '1 of selection*'
      'all of selection*'
      '1 of them'
      'all of them'
      'selection1 or (selection2 and selection3)'
    """
    cond = cond.strip()

    # Handle '1 of selection*' patterns
    m = re.match(r'(\d+)\s+of\s+([\w*?]+)$', cond, re.IGNORECASE)
    if m:
        n = int(m.group(1))
        targets = _expand_pattern(m.group(2).strip(), selections)
        if len(targets) < n:
            raise UnsupportedRule(
                f"Not enough selections for '1 of' pattern: need {n}, got {len(targets)}")
        # Build: (sel1 OR sel2 OR ...) requiring at least n match
        # In KQL we approximate: OR all of them (any match counts as true)
        inner = " or ".join(f"({_sigma_selection_to_kql(selections[s], table)})"
                            for s in targets if s in selections)
        # For exact count matching we'd need subqueries; we approximate with OR
        return f"({inner})" if inner else "true"

    # Handle 'all of selection*'
    m = re.match(r'all\s+of\s+([\w*?]+)$', cond, re.IGNORECASE)
    if m:
        targets = _expand_pattern(m.group(1).strip(), selections)
        if not targets:
            raise UnsupportedRule("No selections match 'all of " + m.group(1) + "'")
        inner = " and ".join(f"({_sigma_selection_to_kql(selections[s], table)})"
                             for s in targets if s in selections)
        return f"({inner})" if inner else "true"

    # Handle '1 of them' / 'all of them' — references the_same, or all unnamed
    if re.match(r'\d+\s+of\s+them$', cond, re.IGNORECASE):
        n_match = re.match(r'(\d+)\s+of\s+them', cond, re.IGNORECASE)
        n = int(n_match.group(1))
        non_filter = {k: v for k, v in selections.items()
                      if not k.startswith("filter_")}
        inner = " or ".join(f"({_sigma_selection_to_kql(v, table)})"
                            for v in non_filter.values())
        return f"({inner})" if inner else "true"

    if re.match(r'all\s+of\s+them$', cond, re.IGNORECASE):
        non_filter = {k: v for k, v in selections.items()
                      if not k.startswith("filter_")}
        inner = " and ".join(f"({_sigma_selection_to_kql(v, table)})"
                             for v in non_filter.values())
        return f"({inner})" if inner else "true"

    # Embedded 'N of pattern' / 'all of pattern' inside a larger condition
    # (e.g. "selection and not 1 of filter_*").  Expand each occurrence to
    # an OR (N of) / AND (all of) group before plain token replacement.
    cond = _OF_PATTERN_RE.sub(
        lambda m: _expand_of_expression(m, selections, table), cond)

    # Handle parenthesized expressions
    cond = _replace_tokens(cond, selections, table)
    return cond


_OF_PATTERN_RE = re.compile(
    r'\b(\d+|all)\s+of\s+([\w*?]+)', re.IGNORECASE)


def _expand_of_expression(m: re.Match, selections: dict[str, dict],
                          table: str) -> str:
    """Expand an embedded 'N of pattern' / 'all of pattern' match to KQL."""
    n = m.group(1).lower()
    targets = [s for s in _expand_pattern(m.group(2), selections)
               if s in selections]
    if not targets:
        raise UnsupportedRule(
            f"No selections match '{m.group(0)}' in condition")
    joiner = " and " if n == "all" else " or "
    inner = joiner.join(
        f"({_sigma_selection_to_kql(selections[s], table)})" for s in targets)
    return f"({inner})"


def _expand_pattern(pattern: str, selections: dict[str, dict]) -> list[str]:
    """Expand 'selection*' into matching selection names."""
    if pattern in ("them",):
        return [k for k in selections if not k.startswith("filter_")]
    pattern = pattern.replace("*", ".*").replace("?", ".")
    try:
        regex = re.compile(f"^{pattern}$")
    except re.error:
        return [pattern] if pattern in selections else []
    return [k for k in selections if regex.match(k)]


def _replace_tokens(cond: str, selections: dict[str, dict], table: str) -> str:
    """Replace selection names in a condition with their KQL equivalents."""
    # Sort by length desc so 'selection1' matches before 'selection'
    names = sorted(selections.keys(), key=len, reverse=True)
    result = cond
    for name in names:
        kql = _sigma_selection_to_kql(selections[name], table)
        # Replace word-boundary occurrences — use a lambda repl to avoid
        # backreference interpretation of \ in KQL strings
        result = re.sub(r'\b' + re.escape(name) + r'\b',
                        lambda m, k=kql: f"({k})", result)
    # Normalize: uppercase AND/OR/NOT
    result = re.sub(r'\band\b', 'and', result, flags=re.IGNORECASE)
    result = re.sub(r'\bor\b', 'or', result, flags=re.IGNORECASE)
    result = re.sub(r'\bnot\b', 'not', result, flags=re.IGNORECASE)
    return result
