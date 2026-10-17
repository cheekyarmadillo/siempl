"""Rank ingest parsers against sample log lines (the sources 'detect parser' endpoint).

Every registered parser is lenient: given any line it returns *some* event (at worst a
GenericEvents fallback), so "did it parse" cannot tell the right parser from a wrong one.
What does differ is how much real data a parser pulled out. A parser that understands the
format fills many fields; a parser that does not leaves its usual envelope fields empty.
So candidates are ranked by (events parsed, mean non-empty fields per event); remaining
ties keep registration order.
"""
from __future__ import annotations

import logging
from typing import Any

from .parsers import get_parser, list_parsers

logger = logging.getLogger(__name__)

_EMPTY = (None, "", "-", [], {})


def _fields(ev: Any) -> dict:
    return ev.fields if hasattr(ev, "fields") else ev.get("fields", {})


def _table(ev: Any) -> str:
    return ev.table if hasattr(ev, "table") else ev.get("table", "")


def _filled(ev: Any) -> int:
    return sum(1 for v in _fields(ev).values() if v not in _EMPTY)


def _run_parser(parser, lines: list[str]) -> list:
    events: list = []
    for line in lines:
        events.extend(parser(line, "detect-test") or [])
    return events


def detect_parsers(lines: list[str], limit: int = 3) -> list[dict]:
    """Return up to *limit* candidate parsers for *lines*, best first."""
    scored: list[tuple[int, float, dict]] = []
    for name in list_parsers():
        parser = get_parser(name)
        if not parser:
            continue
        try:
            events = _run_parser(parser, lines)
        except Exception:
            logger.debug("detect_parsers: parser %s raised", name, exc_info=True)
            continue
        if not events:
            continue
        scored.append((len(events), sum(_filled(e) for e in events) / len(events), {
            "parser": name,
            "tables": list({_table(e) for e in events}),
            "fields": list({k for e in events for k in _fields(e)}),
            "parsed_count": len(events),
        }))
    scored.sort(key=lambda s: (-s[0], -s[1]))  # stable: ties keep registration order
    return [s[2] for s in scored[:limit]]
