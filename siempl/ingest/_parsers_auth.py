"""Auth log parsers built on syslog text: sshd and sudo."""

from __future__ import annotations

import re
from datetime import datetime

from .types import NormalizedEvent

# ── SSH sub-parser ────────────────────────────────────────────────────────────


# sshd auth sub-methods seen in the wild (Debian/PAM appends "/pam").

# NOTE: AuthMethod is normalized to "ssh" for every sshd auth event (the rule

# contract, see docs/RULES.md); the sub-method is kept in LogonType.

_SSHD_METHOD = r"(password|publickey|keyboard-interactive(?:/pam)?|none|hostbased|gssapi-with-mic)"


SSHD_FAIL_RE = re.compile(
    r"Failed\s+" + _SSHD_METHOD + r"\s+for\s+(?:(?:invalid|illegal)\s+user\s+)?(\S+)"
    r"\s+from\s+(\S+)\s+port\s+(\d+)",
    re.I,
)


SSHD_ACCEPT_RE = re.compile(
    r"Accepted\s+" + _SSHD_METHOD + r"\s+for\s+(?:(?:invalid|illegal)\s+user\s+)?(\S+)"
    r"\s+from\s+(\S+)\s+port\s+(\d+)",
    re.I,
)


SSHD_INVALID_USER_RE = re.compile(r"(?:Invalid|Illegal)\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)", re.I)


def _parse_sshd(
    ts: datetime, source_id: str, hostname: str, msg: str, original: str, extra_or_fields: dict
) -> list[NormalizedEvent]:
    """Parse an sshd log message into an AuthEvent."""

    src_ip, user_name, event_result = "", "", "unknown"

    fail_reason = ""

    ssh_method = ""  # password | publickey | keyboard-interactive | ...

    m = SSHD_FAIL_RE.search(msg)

    if m:
        ssh_method = m.group(1).lower().removesuffix("/pam")

        user_name = m.group(2)

        src_ip = m.group(3)

        event_result = "failure"

        fail_reason = msg

    else:
        m = SSHD_INVALID_USER_RE.search(msg)

        if m:
            user_name = m.group(1)

            src_ip = m.group(2)

            event_result = "failure"

            fail_reason = f"Invalid user: {user_name}"

        else:
            m = SSHD_ACCEPT_RE.search(msg)

            if m:
                ssh_method = m.group(1).lower().removesuffix("/pam")

                user_name = m.group(2)

                src_ip = m.group(3)

                event_result = "success"

    # Rule contract (builtin rules 1-3): sshd auth events carry AuthMethod="ssh"

    # and the account being authenticated in TargetUserName (UserName kept for

    # backward compatibility). The wire sub-method lives in LogonType.

    auth_method = "ssh" if event_result != "unknown" else ""

    base_source_type = (extra_or_fields or {}).get("SourceType", "syslog_rfc3164")

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "sshd" if event_result != "unknown" else base_source_type,
        "Message": msg,
        "RawEvent": original,
        "HostName": hostname,
        "UserName": user_name,
        "TargetUserName": user_name,
        "SrcIp": src_ip,
        "EventResult": event_result,
        "AuthMethod": auth_method,
        "LogonType": ssh_method,
        "FailureReason": fail_reason,
        "EventCode": "",
        "EventAction": "login",
    }

    target = "AuthEvents" if event_result != "unknown" else "Syslog"

    # Merge in any caller-provided extra context

    if extra_or_fields:
        for k, v in extra_or_fields.items():
            if k not in fields:
                fields[k] = v

    return [NormalizedEvent(table=target, fields=fields)]


# ── Sudo sub-parser ───────────────────────────────────────────────────────────


SUDO_RE = re.compile(r"(\S+)\s*:\s*TTY=(\S*)\s*;\s*PWD=(\S*)\s*;\s*USER=(\S*)\s*;\s*COMMAND=(.*)", re.I)


SUDO_FAIL_RE = re.compile(r"(\S+)\s*:\s*.*authentication failure", re.I)


def _parse_sudo(
    ts: datetime, source_id: str, hostname: str, msg: str, original: str, extra_or_fields: dict
) -> list[NormalizedEvent]:
    """Parse a sudo log message."""

    event_result = "unknown"

    user_name = ""

    target_user = ""

    fail_reason = ""

    m = SUDO_RE.search(msg)

    if m:
        user_name = m.group(1)

        target_user = m.group(4)

        event_result = "success"

    else:
        m = SUDO_FAIL_RE.search(msg)

        if m:
            user_name = m.group(1)

            event_result = "failure"

            fail_reason = msg

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "sudo",
        "Message": msg,
        "RawEvent": original,
        "HostName": hostname,
        "UserName": user_name,
        "TargetUserName": target_user,
        "EventResult": event_result,
        "AuthMethod": "sudo",
        "FailureReason": fail_reason,
        "EventCode": "",
        "EventAction": "session_elevation",
    }

    target = "AuthEvents" if event_result != "unknown" else "Syslog"

    if extra_or_fields:
        for k, v in extra_or_fields.items():
            if k not in fields:
                fields[k] = v

    return [NormalizedEvent(table=target, fields=fields)]
