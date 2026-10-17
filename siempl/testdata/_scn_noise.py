"""Scenarios 4, 6 and 7: a noisy false-positive rule, a chatty debug source, and an unparsed new source.

Not for: attack chains (_scn_attack.py, _scn_movement.py) or prompt-injection rows (_scn_injection.py).
Scenario 4 feeds the tuning agent; 6 feeds the ingestion optimizer; 7 feeds the onboarding agent.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ._scn_rows import alert, ev, rule, scenario, source

BKP_SRC = "scn-noisy-backup-auth"
BKP_USER = "svc_veeam_bkp"
BKP_IP = "10.42.9.20"
BKP_TARGETS = [("arch-fs-01", 6), ("arch-fs-02", 5), ("hr-sql-01", 5), ("mail-relay-03", 4),
               ("print-srv-02", 4), ("wiki-app-01", 4), ("erp-app-02", 4), ("git-runner-04", 4)]
BKP_CLOSED = 6  # the first six hosts are closed_fp; the last two stay new


def _bkp_failures(now: datetime) -> dict[str, list[dict]]:
    """Failed logons by the backup account per target host, spread over the last 22 hours."""
    out: dict[str, list[dict]] = {}
    tick = 0
    for host, count in BKP_TARGETS:
        rows = []
        for _ in range(count):
            rows.append(ev(BKP_SRC, now, 1320 - tick * 35, EventCode="4625", EventAction="login",
                           EventResult="failure", HostName=host, UserName=BKP_USER,
                           TargetUserName=BKP_USER, SrcIp=BKP_IP, DstIp=None, LogonType="3",
                           AuthMethod="NTLM", FailureReason="Unknown user name or bad password."))
            tick += 1
        out[host] = rows
    return out


def _rules_bkp() -> list[dict]:
    return [rule("scn_fp_any_failed_logon", "Any failed logon (single failure)",
                 "Fires on every failed authentication, with no threshold. Very noisy by design; "
                 "most hits are stale service passwords or expired scheduled tasks.",
                 "1. Check whether the account is a service account\n2. Check the last password change\n"
                 "3. Close as false positive if the account is a known service",
                 "low", 'AuthEvents | where EventResult == "failure"', ["AuthEvents"], ["T1110"],
                 [{"entity_type": "user", "column": "UserName"}, {"entity_type": "host", "column": "HostName"}])]


def noisy_false_positive(now: datetime) -> dict:
    """Backup account fails 36 times across 8 hosts; one low alert per host, six already closed FP."""
    per_host = _bkp_failures(now)
    events = [("AuthEvents", r) for rows in per_host.values() for r in rows]
    cols = ["UserName", "HostName", "SrcIp", "FailureReason", "LogonType"]
    alerts = []
    for idx, (host, _count) in enumerate(BKP_TARGETS):
        status = "closed_fp" if idx < BKP_CLOSED else "new"
        rows = per_host[host]
        alerts.append(alert("scn_fp_any_failed_logon", rows[:5], cols, len(rows), 1300 - idx * 90, status=status,
                            by="user:scenario-loader"))
    return scenario("noisy_false_positive", [source(BKP_SRC, "Windows Security backup (scenario)",
                                                    "windows_json", "AuthEvents")],
                    _rules_bkp(), events, alerts)


CHATTY_SRC = "scn-chatty-debug-syslog"
CHATTY_ROWS = 4000  # debug-level heartbeat rows over 24 hours, no detection value


def chatty_source(now: datetime) -> dict:
    """Debug-level metrics heartbeats at SeverityLevel 7: the optimizer should find a drop filter."""
    events = []
    for i in range(CHATTY_ROWS):
        msg = f"DEBUG poll cycle ok series=cpu.user shard={i % 16} seq={i}"
        events.append(("Syslog", ev(CHATTY_SRC, now, i * 0.36, src_type="syslog5424", Facility="local0",
                                    SeverityLevel=7, AppName="metricsd", ProcessId=2210 + i % 8,
                                    HostName="metrics-collector-02", Message=msg, RawEvent=msg,
                                    EventResult="unknown", EventAction="poll")))
    return scenario("chatty_source", [source(CHATTY_SRC, "metrics collector debug (scenario)",
                                              "syslog5424", "Syslog")], [], events, [])


IOT_SRC = "scn-iot-gateway-raw"
IOT_LINES = [
    ("TLX|v2|dev=GW-7F21|evt=ZONE_ARM|zone=3|user=ops", 300),
    ("TLX|v2|dev=GW-7F21|evt=SENSOR_FAULT|sensor=pir-14|code=0x1F", 240),
    ("TLX|v2|dev=GW-9C03|evt=DOOR_FORCED|door=loading-2", 190),
    ("TLX|v2|dev=GW-7F21|evt=ZONE_DISARM|zone=3|user=ops", 120),
    ("TLX|v2|dev=GW-9C03|evt=HEARTBEAT|fw=2.4.1", 15),
]


def new_unparsed_source(now: datetime) -> dict:
    """A new vendor feed with no parser: pending source, raw lines in GenericEvents."""
    events = []
    for line, minutes_ago in IOT_LINES:
        stamp = (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = f"{line}|ts={stamp}"
        events.append(("GenericEvents", ev(IOT_SRC, now, minutes_ago, src_type="unknown", Message=raw[:200],
                                           RawEvent=raw, EventResult="unknown")))
    src = source(IOT_SRC, "Tellurix gateway (unparsed)", "auto", "GenericEvents", status="pending")
    return scenario("new_unparsed_source", [src], [], events, [])
