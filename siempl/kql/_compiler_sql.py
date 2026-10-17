"""SQL output primitives for the KQL compiler.

Holds the compile error type, the literal renderer and the incremental SQL
builder. Has no compiler state, so the compiler core and its mixins can all
import it without an import cycle.
"""
from __future__ import annotations

from typing import Any

from ._parser import KqlParseError


class KqlCompilerError(KqlParseError):
    """Error during KQL compilation."""

def sql_literal(value):
    """Render a Python value as a safe DuckDB SQL literal."""
    from datetime import date, datetime
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, datetime):
        return "TIMESTAMP '" + value.isoformat(sep=' ') + "'"
    if isinstance(value, date):
        return "DATE '" + value.isoformat() + "'"
    t = str(value)
    if chr(0) in t:
        raise ValueError('NUL character in string literal')
    return "'" + t.replace("'", "''") + "'"

class SqlBuilder:
    """Builds SQL incrementally with proper quoting."""

    def __init__(self):
        self.parts: list[str] = []
        self._params: list[Any] = []

    @property
    def params(self) -> list:
        return list(self._params)

    def add(self, text: str) -> None:
        self.parts.append(text)

    def add_param(self, value: Any) -> str:
        """Add a parameter and return the placeholder."""
        # ADR: values inlined as escaped SQL literals; positional params broke across stages.
        return sql_literal(value)

    def build(self) -> str:
        return "".join(self.parts)

    def __str__(self) -> str:
        return self.build()
