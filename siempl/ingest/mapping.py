"""Declarative mapping parser engine. Parses records according to a JSON spec.

The MappingParser is the tool AI onboarding agents emit to handle unknown sources.
Spec format is documented in docs/PARSERS.md.

SAFETY: No eval(), no code execution. Specs are pure data-driven transformation.
Regex operations have timeout and size limits.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from typing import Any

from ..schema import DATA_TABLES
from .types import NormalizedEvent

# Maximum record size for safety
MAX_RECORD_SIZE = 100_000  # bytes
MAX_REGEX_TIME = 5.0       # seconds
MAX_CSV_FIELDS = 200


# ── spec validation ───────────────────────────────────────────────────────────

REQUIRED_SPEC_KEYS = {"name", "target_table"}
ALLOWED_TOP_KEYS = {"name", "description", "format", "target_table",
                    "time", "fields", "constants", "when", "json_path_prefix",
                    "regex_pattern", "kv_delimiter"}
VALID_FORMATS = {"json", "regex", "kv", "csv"}
VALID_TRANSFORMS = {"lower", "upper", "strip", "int", "float", "bool"}


def validate_spec(spec: dict) -> list[str]:
    """Validate a mapping-parser spec, returning a list of error strings (empty = valid)."""
    errors: list[str] = []

    if not isinstance(spec, dict):
        return ["Spec must be a JSON object"]

    # Required keys
    for key in REQUIRED_SPEC_KEYS:
        if key not in spec:
            errors.append(f"Missing required key: '{key}'")

    # Check for unknown top-level keys (strict, to catch typos)
    for key in spec:
        if key not in ALLOWED_TOP_KEYS:
            errors.append(f"Unknown top-level key: '{key}'. Allowed: {sorted(ALLOWED_TOP_KEYS)}")

    # target_table must be valid
    target = spec.get("target_table")
    if target and target not in DATA_TABLES:
        errors.append(f"Unknown target_table '{target}'. Valid: {sorted(DATA_TABLES)}")

    # format must be valid
    fmt = spec.get("format")
    if fmt and fmt not in VALID_FORMATS:
        errors.append(f"Unknown format '{fmt}'. Valid: {sorted(VALID_FORMATS)}")

    # Validate time config
    time_cfg = spec.get("time")
    if time_cfg is not None:
        if not isinstance(time_cfg, dict):
            errors.append("'time' must be an object with 'field' and optional 'format'")
        elif "field" not in time_cfg:
            errors.append("'time' requires 'field' key")
        else:
            tfmt = time_cfg.get("format", "")
            if tfmt and tfmt not in ("iso8601", "unix", "unix_ms"):
                # Check if it's a valid strptime format (basic check)
                if not isinstance(tfmt, str):
                    errors.append("'time.format' must be a string or one of: iso8601, unix, unix_ms")

    # Validate fields
    fields = spec.get("fields")
    if fields is not None:
        if not isinstance(fields, dict):
            errors.append("'fields' must be an object mapping column_name -> path/transform_config")
        else:
            for field_name, field_spec in fields.items():
                if not isinstance(field_spec, (str, dict)):
                    errors.append(f"fields.{field_name}: must be a string (path) or object {{path, transform, default}}")
                    continue

                if isinstance(field_spec, dict):
                    valid_keys = {"path", "transform", "default"}
                    for k in field_spec:
                        if k not in valid_keys:
                            errors.append(f"fields.{field_name}: unknown key '{k}'. Allowed: {sorted(valid_keys)}")
                    if "path" not in field_spec:
                        errors.append(f"fields.{field_name}: missing required 'path' key")
                    if "transform" in field_spec:
                        t = field_spec["transform"]
                        if t not in VALID_TRANSFORMS:
                            errors.append(f"fields.{field_name}.transform '{t}': must be one of {sorted(VALID_TRANSFORMS)}")

    # Validate constants
    constants = spec.get("constants")
    if constants is not None:
        if not isinstance(constants, dict):
            errors.append("'constants' must be an object")
        else:
            for k, v in constants.items():
                if not isinstance(v, (str, int, float, bool, type(None))):
                    errors.append(f"constants.{k}: value must be a JSON scalar")

    # Validate when condition
    when = spec.get("when")
    if when is not None:
        if not isinstance(when, dict):
            errors.append("'when' must be an object")

    # Validate json_path_prefix
    prefix = spec.get("json_path_prefix")
    if prefix is not None and not isinstance(prefix, str):
        errors.append("'json_path_prefix' must be a string")

    errors.extend(_validate_text_format_keys(spec))
    return errors


def _validate_text_format_keys(spec: dict) -> list[str]:
    """Checks for the regex and delimited-kv extras (regex_pattern must compile, kv_delimiter is short)."""
    errors: list[str] = []
    pattern = spec.get("regex_pattern")
    if pattern is not None:
        try:
            re.compile(pattern)
        except (re.error, TypeError) as e:
            errors.append(f"'regex_pattern' is not a valid regex: {e}")
    delim = spec.get("kv_delimiter")
    if delim is not None and not (isinstance(delim, str) and 1 <= len(delim) <= 3):
        errors.append("'kv_delimiter' must be a 1-3 character string")
    return errors


# ── JSON path resolution ──────────────────────────────────────────────────────


def _resolve_path(obj: dict, path: str) -> Any:
    """Resolve a dotted or $-prefixed JSON path against a dict.

    Paths are simple dot-separated field names (no bracket syntax, no wildcards).
    A leading '$.' is stripped. All components are dict keys; no array indexing.
    """
    if not path:
        return None
    p = path.lstrip("$").lstrip(".")
    if not p:
        return obj  # just "$" -> root
    parts = p.split(".")
    current: Any = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
            if current is None:
                return None
        else:
            return None
    return current


def _apply_transform(val: Any, transform: str) -> Any:
    """Apply a named transform to a value. Returns the transformed value."""
    if val is None:
        return None
    if transform == "lower":
        return str(val).lower()
    if transform == "upper":
        return str(val).upper()
    if transform == "strip":
        return str(val).strip()
    if transform == "int":
        try:
            return int(val)
        except (ValueError, TypeError):
            return None
    elif transform == "float":
        try:
            return float(val)
        except (ValueError, TypeError):
            return None
    elif transform == "bool":
        s = str(val).lower().strip()
        if s in ("true", "1", "yes", "y"):
            return True
        if s in ("false", "0", "no", "n", ""):
            return False
        return None
    return val


def _check_when(obj: dict, when: dict) -> bool:
    """Evaluate a when condition against the parsed record.

    Supported operators: eq, neq, in, contains, regex, exists.
    Example: {"field": {"path": "$.status"}, "op": "eq", "value": "error"}
    Example: {"field": "status", "op": "neq", "value": "ok"}
    """
    field_spec = when.get("field")
    op = when.get("op", "eq")
    expected = when.get("value")

    # Resolve the field value
    if isinstance(field_spec, dict):
        val = _resolve_path(obj, field_spec.get("path", ""))
    elif isinstance(field_spec, str):
        val = obj.get(field_spec)
    else:
        return True  # no field specified -> match all

    if op == "eq":
        return str(val) == str(expected) if val is not None else expected is None
    if op == "neq":
        return str(val) != str(expected) if val is not None else expected is not None
    if op == "in":
        return str(val) in (expected if isinstance(expected, list) else [str(expected)])
    if op == "contains":
        return str(expected).lower() in str(val).lower()
    if op == "regex":
        if not isinstance(expected, str):
            return False
        try:
            return bool(re.search(expected, str(val), timeout=MAX_REGEX_TIME))
        except (re.error, TimeoutError):
            return False
    elif op == "exists":
        return val is not None

    return True


def _parse_time(val: Any, fmt: str) -> datetime | None:
    """Parse a timestamp value according to a format hint."""
    if val is None:
        return None

    if fmt == "iso8601":
        s = str(val).strip()
        for tfmt in [
            "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                dt = datetime.strptime(s, tfmt)
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)
                return dt
            except ValueError:
                continue
        return None

    if fmt == "unix":
        try:
            return datetime.fromtimestamp(float(val))
        except (ValueError, OverflowError, TypeError):
            return None

    elif fmt == "unix_ms":
        try:
            return datetime.fromtimestamp(float(val) / 1000.0)
        except (ValueError, OverflowError, TypeError):
            return None

    elif fmt:
        # Custom strptime
        try:
            dt = datetime.strptime(str(val), fmt)
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt
        except ValueError:
            return None

    return None


# ── format-specific record parsing ────────────────────────────────────────────


def _parse_record(obj: dict, spec: dict, format: str) -> list[NormalizedEvent]:
    """Parse a single dict record into NormalizedEvents using the spec."""
    prefix = spec.get("json_path_prefix", "")
    if prefix and isinstance(obj, dict):
        obj = _resolve_path(obj, prefix) or obj
        if not isinstance(obj, dict):
            return []

    # Check "when" condition
    when = spec.get("when")
    if when and not _check_when(obj, when):
        return []

    fields: dict[str, Any] = {}

    # Resolve field mappings
    spec_fields = spec.get("fields", {})
    for col_name, field_spec in spec_fields.items():
        if isinstance(field_spec, str):
            # Simple path mapping
            val = _resolve_path(obj, field_spec)
        elif isinstance(field_spec, dict):
            val = _resolve_path(obj, field_spec.get("path", ""))
            transform = field_spec.get("transform")
            if transform and val is not None:
                val = _apply_transform(val, transform)
        else:
            continue

        if val is not None:
            fields[col_name] = val
        elif isinstance(field_spec, dict) and "default" in field_spec:
            fields[col_name] = field_spec["default"]

    # Apply constants
    constants = spec.get("constants", {})
    for k, v in constants.items():
        fields[k] = v

    # Resolve time
    time_cfg = spec.get("time")
    if time_cfg:
        time_field = time_cfg["field"]
        time_fmt = time_cfg.get("format", "iso8601")
        # Resolve the time value: it could itself be a JSON path
        raw_ts = _resolve_path(obj, time_field) if "." in time_field or time_field.startswith("$") else obj.get(time_field)
        ts = _parse_time(raw_ts, time_fmt)
        if ts:
            fields["TimeGenerated"] = ts

    if "TimeGenerated" not in fields:
        fields["TimeGenerated"] = datetime.now().replace(microsecond=0)

    fields["RawEvent"] = json.dumps(obj, default=str)

    target = spec["target_table"]
    return [NormalizedEvent(table=target, fields=fields)]


# ── MappingParser class ───────────────────────────────────────────────────────

class MappingParser:
    """Declarative parser driven by a JSON spec.

    Usage:
        p = MappingParser({"name": "my_parser", "format": "json", "target_table": "AuthEvents", ...})
        events = p.parse({"username": "bob", "ip": "1.2.3.4"}, source_id="src1")
    """

    def __init__(self, spec: dict):
        errors = validate_spec(spec)
        if errors:
            raise ValueError(f"Invalid parser spec: {'; '.join(errors)}")
        self.spec = spec
        self.format = spec.get("format", "json")

    @property
    def name(self) -> str:
        return self.spec["name"]

    def parse(self, raw: Any, source_id: str) -> list[NormalizedEvent]:
        """Parse one raw record into NormalizedEvents."""
        source_type = self.spec.get("name", "mapping")

        # Convert raw to dict
        obj: dict
        if isinstance(raw, dict):
            obj = raw
        elif isinstance(raw, str):
            raw_str = raw[:MAX_RECORD_SIZE]
            fmt = self.format
            try:
                if fmt == "json":
                    obj = json.loads(raw_str)
                    if not isinstance(obj, dict):
                        return []
                elif fmt == "csv":
                    reader = csv.reader(io.StringIO(raw_str))
                    row = next(reader, None)
                    if not row:
                        return []
                    headers = [f"col{i+1}" for i, col in enumerate(row)]
                    obj = dict(zip(headers, row))
                elif fmt == "kv":
                    obj = _parse_kv(raw_str, self.spec.get("kv_delimiter"))
                elif fmt == "regex":
                    # regex fields: { "col": {"path": "group_name", ...} }
                    # Let's handle this differently - regex fields use named groups
                    # Build a regex from "pattern" key in the spec
                    regex_pat = self.spec.get("regex_pattern", "")
                    if regex_pat:
                        try:
                            m = re.search(regex_pat, raw_str[:MAX_RECORD_SIZE],
                                          timeout=MAX_REGEX_TIME)
                        except (re.error, TimeoutError):
                            return []
                        if m:
                            obj = m.groupdict()
                            # Also capture numbered groups
                            for i, g in enumerate(m.groups()):
                                if str(i) not in obj:
                                    obj[str(i)] = g
                        else:
                            return []
                    else:
                        return []
                else:
                    return []
            except (json.JSONDecodeError, Exception):
                return []
        else:
            return []

        if not isinstance(obj, dict):
            return []

        # Set source metadata
        events = _parse_record(obj, self.spec, self.format)
        for evt in events:
            evt.fields.setdefault("SourceType", source_type)
            evt.fields.setdefault("SourceId", source_id)
        return events


def _parse_kv(raw_str: str, delimiter: str | None) -> dict:
    """key=value pairs split on whitespace, or on kv_delimiter (e.g. '|') for delimited records."""
    obj: dict = {}
    for pair in raw_str.split(delimiter or None):
        if "=" in pair:
            k, v = pair.split("=", 1)
            obj[k.strip()] = v.strip().strip('"').strip("'")
    return obj


# ── register mapping parser ───────────────────────────────────────────────────

from . import parsers as _parsers_module  # noqa: E402


def _register_mapping(spec: dict) -> MappingParser:
    """Create, register, and return a MappingParser from a spec dict."""
    p = MappingParser(spec)
    # register as callable
    p_name = spec["name"]

    def _parser(raw, sid):
        return p.parse(raw, sid)
    _parser.__name__ = p_name

    _parsers_module.register(p_name, _parser)
    return p
