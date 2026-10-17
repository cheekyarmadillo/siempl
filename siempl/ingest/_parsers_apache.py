"""Apache / nginx combined access-log parser."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ._parsers_core import _utcnow, register
from .types import NormalizedEvent

# ── Apache/Nginx combined log parser ──────────────────────────────────────────


APACHE_COMBINED_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s*'
    r'("([^"]*)"\s+)?("([^"]*)")?'
)


MONTHS_APACHE = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@register("apache_combined")
def parse_apache_combined(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse Apache/Nginx combined access log format."""

    msg = raw if isinstance(raw, str) else str(raw)

    original = msg

    m = APACHE_COMBINED_RE.match(msg)

    if not m:
        return [
            NormalizedEvent(
                table="GenericEvents",
                fields={
                    "TimeGenerated": _utcnow(),
                    "SourceId": source_id,
                    "SourceType": "apache_combined",
                    "Message": msg,
                    "RawEvent": original,
                    "EventCode": "",
                    "EventAction": "",
                    "EventResult": "unknown",
                },
            )
        ]

    ip, _, user, ts_str, method, url, version, status, size, _, referrer, _, ua = m.groups()

    ts = _utcnow()

    if ts_str:
        try:
            # 10/Oct/2000:13:55:36 -0700

            parts = ts_str.split(":")

            day_mon_year = parts[0].split("/")

            if len(day_mon_year) == 3:
                day = int(day_mon_year[0])

                mon = MONTHS_APACHE.get(day_mon_year[1], 1)

                year = int(day_mon_year[2])

                hh = int(parts[1])

                mm = int(parts[2])

                ss = int(parts[3].split()[0])

                ts = datetime(year, mon, day, hh, mm, ss)

        except (ValueError, IndexError):
            pass

    event_result = "failure" if status and int(status) >= 400 else "success"

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "apache_combined",
        "Message": msg,
        "RawEvent": original,
        "SrcIp": ip,
        "UserName": user if user != "-" else "",
        "HttpMethod": method,
        "Url": url,
        "UrlPath": url.split("?")[0] if url else "",
        "StatusCode": int(status) if status else None,
        "UserAgent": ua if ua and ua != "-" else "",
        "Referrer": referrer if referrer and referrer != "-" else "",
        "Bytes": int(size) if size and size != "-" else None,
        "EventCode": str(status),
        "EventAction": method,
        "EventResult": event_result,
    }

    return [NormalizedEvent(table="WebAccess", fields=fields)]
