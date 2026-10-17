"""Syslog parsers: RFC 3164 (BSD) and RFC 5424."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ._parsers_auth import _parse_sshd, _parse_sudo
from ._parsers_core import _utcnow, register
from .types import NormalizedEvent

# ── generic helpers ───────────────────────────────────────────────────────────


# RFC 3164 syslog PRI parsing

SYSLOG_PRI_RE = re.compile(r"^<(\d{1,3})>(.*)")


# RFC 3164 header: Mmm dd HH:MM:SS hostname

SYSLOG_HEADER3164_RE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)"
)


MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}


# ── syslog parsers ────────────────────────────────────────────────────────────


@register("syslog_rfc3164")
def parse_syslog_rfc3164(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse RFC 3164 BSD syslog messages, with SSH/Sudo sub-parsing."""

    msg = raw if isinstance(raw, str) else str(raw)

    original = msg

    now = _utcnow()

    pri = 13  # default: user.notice

    m = SYSLOG_PRI_RE.match(msg)

    severity = 5

    facility = 1

    if m:
        pri = int(m.group(1))

        facility, severity = pri // 8, pri % 8

        msg = m.group(2)

    header = SYSLOG_HEADER3164_RE.match(msg)

    ts = now

    hostname = ""

    if header:
        mon, day, hh, mm, ss, hostname = header.groups()

        ts = datetime(now.year, MONTHS[mon.lower()], int(day), int(hh), int(mm), int(ss))

        msg = msg[header.end() :].lstrip()

        if msg.startswith(":"):
            msg = msg[1:].lstrip()  # some senders add a colon

    else:
        # Try to extract hostname from start of message

        parts = msg.split(None, 1)

        if parts:
            hostname = parts[0]

            msg = parts[1] if len(parts) > 1 else ""

    # Extract app name from the message start (e.g. "sshd[123]: ...")

    app_name = ""

    proc_id = None

    msg_body = msg

    app_match = re.match(r"^(\S+?)(?:\[(\d+)\])?:\s*(.*)", msg)

    if app_match:
        app_name = app_match.group(1)

        proc_id = int(app_match.group(2)) if app_match.group(2) else None

        msg_body = app_match.group(3)

    # Coarse event result

    event_result = "unknown"

    msg_lower = msg_body.lower()

    if any(w in msg_lower for w in ("failed", "failure", "invalid", "error", "denied", "refused")):
        event_result = "failure"

    elif any(w in msg_lower for w in ("accepted", "successful", "started", "session opened")):
        event_result = "success"

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "syslog_rfc3164",
        "Message": msg_body,
        "RawEvent": original,
        "HostName": hostname,
        "AppName": app_name,
        "ProcessId": proc_id,
        "Facility": str(facility),
        "SeverityLevel": severity,
        "EventCode": "",
        "EventAction": "",
        "EventResult": event_result,
    }

    # Sub-parse sshd/sudo to produce AuthEvents

    if app_name == "sshd":
        return _parse_sshd(ts, source_id, hostname, msg_body, original, extra_or_fields=fields)

    if app_name == "sudo":
        return _parse_sudo(ts, source_id, hostname, msg_body, original, extra_or_fields=fields)

    return [NormalizedEvent(table="Syslog", fields=fields)]


@register("syslog_rfc5424")
def parse_syslog_rfc5424(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse RFC 5424 IETF syslog messages, with SSH/Sudo sub-parsing."""

    msg = raw if isinstance(raw, str) else str(raw)

    original = msg

    now = _utcnow()

    pri = 13

    m = SYSLOG_PRI_RE.match(msg)

    severity, facility = 5, 1

    if m:
        pri = int(m.group(1))

        facility, severity = pri // 8, pri % 8

        msg = m.group(2)

    # RFC 5424 header: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID

    parts = msg.split(" ", 6)

    timestr = parts[1] if len(parts) > 1 else "-"

    hostname = parts[2] if len(parts) > 2 else "-"

    app_name = parts[3] if len(parts) > 3 else "-"

    proc_id_str = parts[4] if len(parts) > 4 else "-"

    rest = parts[6] if len(parts) > 6 else ""

    ts = now

    if timestr and timestr != "-" and timestr != "NILVALUE":
        try:
            # Accept ISO 8601 with or without timezone

            timestr_clean = timestr.replace("T", " ")

            ts = datetime.fromisoformat(timestr_clean.replace("Z", "+00:00"))

            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)

        except (ValueError, TypeError):
            pass

    if hostname == "-" or hostname == "NILVALUE":
        hostname = ""

    if app_name == "-" or app_name == "NILVALUE":
        app_name = ""

    proc_id = None

    if proc_id_str not in ("-", "NILVALUE"):
        try:
            proc_id = int(proc_id_str)

        except (ValueError, TypeError):
            pass

    # Structured data and message

    sd = {}

    msg_body = rest

    if rest.startswith("["):
        idx = rest.find("] ")

        if idx >= 0:
            sd_str = rest[1:idx]

            msg_body = rest[idx + 2 :]

            # Simple structured data extraction (skip full SD-ID parsing for now)

            for pair in sd_str.split():
                if "=" in pair:
                    k, v = pair.split("=", 1)

                    sd[k] = v.strip('"')

    # Coarse event result

    event_result = "unknown"

    msg_lower = msg_body.lower()

    if any(w in msg_lower for w in ("failed", "failure", "invalid", "error", "denied", "refused")):
        event_result = "failure"

    elif any(w in msg_lower for w in ("accepted", "successful", "started", "session opened")):
        event_result = "success"

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "syslog_rfc5424",
        "Message": msg_body,
        "RawEvent": original,
        "HostName": hostname,
        "AppName": app_name,
        "ProcessId": proc_id,
        "Facility": str(facility),
        "SeverityLevel": severity,
        "EventCode": "",
        "EventAction": "",
        "EventResult": event_result,
    }

    # Sub-parse sshd/sudo

    if app_name == "sshd":
        return _parse_sshd(ts, source_id, hostname, msg_body, original, extra_or_fields=fields)

    if app_name == "sudo":
        return _parse_sudo(ts, source_id, hostname, msg_body, original, extra_or_fields=fields)

    return [NormalizedEvent(table="Syslog", fields=fields)]
