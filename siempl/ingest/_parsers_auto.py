"""Format auto-detection: sniff the input shape and dispatch to the matching parser (auto_parse)."""

from __future__ import annotations

import json
import re
from typing import Any

from ._parsers_apache import parse_apache_combined
from ._parsers_cef import parse_cef
from ._parsers_core import _as_dict, _utcnow
from ._parsers_json import parse_generic_json
from ._parsers_syslog import SYSLOG_PRI_RE, parse_syslog_rfc3164, parse_syslog_rfc5424
from ._parsers_windows import parse_windows_json
from ._parsers_winxml import parse_windows_xml
from ._parsers_zeek import parse_zeek_conn, parse_zeek_dns
from .types import NormalizedEvent


def _looks_like_cef(raw: Any) -> bool:

    s = raw if isinstance(raw, str) else ""

    return s.strip().startswith("CEF:")


def _looks_like_syslog(raw: Any) -> bool:

    s = raw if isinstance(raw, str) else ""

    return bool(SYSLOG_PRI_RE.match(s.strip()))


def _looks_like_apache(raw: Any) -> bool:

    s = raw if isinstance(raw, str) else ""

    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+\s+", s.strip()))


def _looks_like_windows(obj: dict) -> bool:

    # Has EventID or event_id keys; or typical Winlogbeat structure

    return (
        "EventID" in obj
        or "event_id" in obj
        or "event_data" in obj
        or "EventData" in obj
        or ("Channel" in obj and "Provider" in obj)
    )


def auto_parse(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Sniff the record and choose the best parser. Falls back to GenericEvents."""

    # CEF

    if _looks_like_cef(raw):
        return parse_cef(raw, source_id)

    # Syslog

    if _looks_like_syslog(raw):
        msg = raw if isinstance(raw, str) else str(raw)

        # Try 5424 first (has structured data), then fallback to 3164

        m = SYSLOG_PRI_RE.match(msg.strip())

        if m:
            after = m.group(2)

            if re.match(r"^\d\s", after):
                return parse_syslog_rfc5424(raw, source_id)

            return parse_syslog_rfc3164(raw, source_id)

    # Apache

    if _looks_like_apache(raw):
        return parse_apache_combined(raw, source_id)

    # XML (Windows Event Log XML)

    if isinstance(raw, str) and raw.strip().startswith("<Event"):
        return parse_windows_xml(raw, source_id)

    # JSON array of OCSF events
    if isinstance(raw, str) and raw.lstrip().startswith("["):
        try:
            _arr = json.loads(raw)
        except json.JSONDecodeError:
            _arr = None
        if isinstance(_arr, list) and _arr and all(isinstance(x, dict) for x in _arr):
            from .ocsf import looks_like_ocsf, parse_ocsf

            if all(looks_like_ocsf(x) for x in _arr):
                return parse_ocsf(_arr, source_id)

    # JSON

    obj = _as_dict(raw)

    if isinstance(obj, dict):
        from .ocsf import looks_like_ocsf, parse_ocsf

        if looks_like_ocsf(obj):
            return parse_ocsf(obj, source_id)
        if _looks_like_windows(obj):
            return parse_windows_json(obj, source_id)

        # Zeek signature: has "id.orig_h" or "uid" + conn/DNS fields

        if "uid" in obj and ("id.orig_h" in obj or "query" in obj):
            if "query" in obj:
                return parse_zeek_dns(obj, source_id)

            return parse_zeek_conn(obj, source_id)

        return parse_generic_json(obj, source_id)

    # String fallback

    return [
        NormalizedEvent(
            table="GenericEvents",
            fields={
                "TimeGenerated": _utcnow(),
                "SourceId": source_id,
                "SourceType": "unknown",
                "Message": str(raw)[:1000],
                "RawEvent": str(raw),
                "EventCode": "",
                "EventAction": "",
                "EventResult": "unknown",
            },
        )
    ]
