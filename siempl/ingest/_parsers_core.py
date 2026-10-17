"""Parser registry and shared helpers for the built-in parsers (register, get_parser, list_parsers).

Not parsers themselves: format-specific parsers live in the sibling _parsers_*.py modules and register here."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .types import NormalizedEvent

# ── parser type ───────────────────────────────────────────────────────────────


Parser = Callable[[Any, str], list[NormalizedEvent]]


_registry: dict[str, Parser] = {}


def register(name: str, parser: Parser | None = None):
    """Decorator or function to register a named parser."""

    if parser is not None:
        _registry[name] = parser

        return parser

    def dec(fn: Parser):

        _registry[name] = fn

        return fn

    return dec


def get_parser(name: str) -> Parser | None:

    return _registry.get(name)


def list_parsers() -> dict[str, str]:

    return {k: (v.__doc__ or "").split("\n")[0].strip() for k, v in _registry.items()}


def _utcnow() -> datetime:

    return datetime.now(UTC).replace(tzinfo=None)


def _make_extra(raw_fields: dict, *keep_keys: str) -> dict:
    """Collect fields not in keep_keys into Extra."""

    extra = {}

    for k, v in raw_fields.items():
        if k not in keep_keys:
            extra[k] = v

    return extra


def _json_get(obj: dict, path: str) -> Any:
    """Simple dotted-path resolution on a dict."""

    parts = path.split(".")

    current: Any = obj

    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)

            if current is None:
                return None

        else:
            return None

    return current


def _parse_json_timestamp(val: Any) -> datetime | None:
    """Try to parse various timestamp formats from JSON."""

    if val is None:
        return None

    if isinstance(val, datetime):
        return val

    s = str(val).strip()

    if not s:
        return None

    # Unix timestamp in seconds or ms

    try:
        n = float(s)

        if 1e10 < n < 1e12:  # milliseconds
            n /= 1000.0

        if 1e6 < n < 1e15:
            return datetime.fromtimestamp(n)

    except (ValueError, OverflowError):
        pass

    # ISO 8601

    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(s, fmt)

            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)

            return dt

        except ValueError:
            continue

    return None


# ── auto-detection ────────────────────────────────────────────────────────────


def _as_dict(raw: Any) -> dict | None:

    if isinstance(raw, dict):
        return raw

    if isinstance(raw, str):
        try:
            return json.loads(raw)

        except json.JSONDecodeError:
            return None

    return None
