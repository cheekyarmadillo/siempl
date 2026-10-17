"""Shared types for the ingest package. Separate module to avoid circular imports."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schema import DATA_TABLES


@dataclass
class NormalizedEvent:
    """A single event normalized to a target table + column-mapped fields."""
    table: str
    fields: dict[str, Any]

    def __post_init__(self):
        if self.table not in DATA_TABLES:
            raise ValueError(f"Unknown table '{self.table}'. Valid: {list(DATA_TABLES)}")


@dataclass
class IngestResult:
    """Outcome of a single ingest() call."""
    received: int = 0
    inserted: int = 0
    dropped: int = 0            # matched by filters
    failed: int = 0             # parse errors etc.
    tables: dict[str, int] = field(default_factory=dict)  # table -> number inserted
    errors: list[str] = field(default_factory=list)
