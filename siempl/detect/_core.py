"""Shared primitives for the detect package: the UnsupportedRule error, JSON column helpers, SQL string escaping."""
from __future__ import annotations

import json
from typing import Any


class UnsupportedRule(Exception):
    """A Sigma or Sentinel rule cannot be converted.  *reason* is user-presentable."""
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _json(obj: Any) -> str:
    return json.dumps(obj, default=str)


def _json_list(obj: Any) -> str | None:
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj
    return _json(obj)


def _from_json(raw: Any) -> Any:
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw
    return raw


def _escape_sql_str(s: str) -> str:
    return s.replace("'", "''")
