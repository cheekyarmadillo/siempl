"""Windows Event Log JSON parser (winlogbeat / NXLog style) and its field helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from ._parsers_core import _json_get, _parse_json_timestamp, _utcnow, register
from .types import NormalizedEvent

# ── Windows event JSON parser ─────────────────────────────────────────────────


# Winlogbeat schema (Elastic Winlogbeat / OTRF Security-Datasets format)

# event_data is a dict under the record


# EventID -> target table mapping

WIN_EVENT_TABLE = {
    "4624": "AuthEvents",
    "4625": "AuthEvents",
    "4688": "ProcessEvents",
    "1": "ProcessEvents",  # Sysmon 1: process creation
    "3": "NetworkEvents",  # Sysmon 3: network connection
    "22": "NetworkEvents",  # Sysmon 22: DNS event
    "8": "ProcessEvents",  # Sysmon 8: CreateRemoteThread (ProcessEvents for now)
    "11": "FileEvents",  # Sysmon 11: FileCreate
}


WIN_EVENT_ACTION = {
    "4624": "login",
    "4625": "login",
    "4688": "process_start",
    "1": "process_start",
    "3": "network_connect",
    "22": "dns_query",
    "11": "file_create",
}


def _resolve_win_field(evt: dict, *candidates: str) -> str | None:
    """Look for a field in the Windows event, trying several candidate paths.



    Typical structures:

      - Winlogbeat: {"event_data": {"TargetUserName": "..."}}

      - OTRF: {"TargetUserName": "..."} (flat)

    """

    for cand in candidates:
        # Try dotted path

        val = _json_get(evt, cand)

        if val is not None and str(val).strip() != "":
            return str(val)

        # Try last component as flat key

        last = cand.split(".")[-1]

        if last in evt and evt[last] is not None and str(evt[last]).strip() != "":
            return str(evt[last])

    return None


def _win_raw_fallback(raw: str, source_id: str) -> NormalizedEvent:
    """Text that is not valid JSON: keep it (first 1000 chars) as Message in GenericEvents."""
    return NormalizedEvent(
        table="GenericEvents",
        fields={
            "TimeGenerated": _utcnow(),
            "SourceId": source_id,
            "SourceType": "windows_json",
            "Message": raw[:1000],
            "RawEvent": raw,
            "EventCode": "",
            "EventAction": "",
            "EventResult": "unknown",
        },
    )


def _win_event_data(obj: dict) -> dict:
    """The EventData container (event_data / EventData), or the event itself when it is missing or not a dict."""
    edata = obj.get("event_data", obj.get("EventData", obj))
    return edata if isinstance(edata, dict) else obj


def _win_event_id(obj: dict, edata: dict) -> str:
    event_id = str(_resolve_win_field(obj, "event_id", "EventID", "event.code") or "")
    if not event_id:
        for k in ("EventID", "event_id", "Id"):
            if k in edata:
                event_id = str(edata[k])
                break
    return event_id


def _win_timestamp(obj: dict) -> datetime:
    ts = _utcnow()
    ts_val = _resolve_win_field(obj, "@timestamp", "TimeCreated", "timestamp")
    if ts_val:
        dt = _parse_json_timestamp(ts_val)
        if dt:
            ts = dt
    return ts


def _win_common_fields(obj: dict, source_id: str, event_id: str) -> dict:
    hostname = _resolve_win_field(obj, "host.name", "Computer", "computer_name", "hostname") or ""
    event_result = "success" if event_id == "4624" else ("failure" if event_id == "4625" else "unknown")
    return {
        "TimeGenerated": _win_timestamp(obj),
        "SourceId": source_id,
        "SourceType": "windows_json",
        "EventCode": event_id,
        "EventAction": WIN_EVENT_ACTION.get(event_id, ""),
        "EventResult": event_result,
        "HostName": hostname,
        "Message": obj.get("message", "") or "",
        "RawEvent": json.dumps(obj, default=str),
    }


def _fill_win_auth(fields: dict, edata: dict) -> None:
    fields["UserName"] = _resolve_win_field(edata, "TargetUserName", "user.name") or ""
    fields["TargetUserName"] = fields["UserName"]
    fields["SrcIp"] = _resolve_win_field(edata, "IpAddress", "SrcIp", "source.ip") or ""
    fields["LogonType"] = _resolve_win_field(edata, "LogonType") or ""
    fields["FailureReason"] = _resolve_win_field(edata, "FailureReason", "Status") or ""
    fields["AuthMethod"] = _resolve_win_field(edata, "AuthenticationPackageName") or ""


def _fill_win_process_identity(fields: dict, edata: dict) -> None:
    fields["ProcessName"] = _resolve_win_field(edata, "NewProcessName", "Image", "process.name") or ""
    fields["ProcessPath"] = _resolve_win_field(edata, "Image", "process.path") or ""
    fields["ProcessCmdLine"] = _resolve_win_field(edata, "CommandLine", "process.command_line") or ""
    fields["ProcessId"] = int(_resolve_win_field(edata, "NewProcessId", "ProcessId", "process.pid") or 0) or None


def _fill_win_process_parent(fields: dict, edata: dict) -> None:
    fields["ParentProcessName"] = _resolve_win_field(edata, "ParentImage", "ParentProcessName") or ""
    fields["ParentProcessId"] = int(_resolve_win_field(edata, "ParentProcessId", "process.parent.pid") or 0) or None
    fields["ParentCmdLine"] = _resolve_win_field(edata, "ParentCommandLine") or ""
    fields["FileHash"] = _resolve_win_field(edata, "Hashes", "file.hash.sha256") or ""
    fields["IntegrityLevel"] = _resolve_win_field(edata, "IntegrityLevel") or ""
    fields["UserName"] = _resolve_win_field(edata, "User", "user.name") or ""


def _fill_win_process(fields: dict, edata: dict) -> None:
    _fill_win_process_identity(fields, edata)
    _fill_win_process_parent(fields, edata)


def _fill_win_network(fields: dict, edata: dict) -> None:
    fields["SrcIp"] = _resolve_win_field(edata, "SourceIp", "src_ip", "source.ip") or ""
    fields["DstIp"] = _resolve_win_field(edata, "DestinationIp", "dst_ip", "destination.ip") or ""
    fields["SrcPort"] = int(_resolve_win_field(edata, "SourcePort", "src_port") or 0) or None
    fields["DstPort"] = int(_resolve_win_field(edata, "DestinationPort", "dst_port") or 0) or None
    fields["Protocol"] = _resolve_win_field(edata, "Protocol") or ""
    fields["DnsQuery"] = _resolve_win_field(edata, "QueryName", "dns.question.name") or ""
    fields["ProcessName"] = _resolve_win_field(edata, "Image", "process.name") or ""


def _fill_win_file(fields: dict, edata: dict) -> None:
    fields["FilePath"] = _resolve_win_field(edata, "TargetFilename", "file.path") or ""
    fields["FileName"] = _resolve_win_field(edata, "TargetFilename", "file.name") or ""
    fields["FileHash"] = _resolve_win_field(edata, "Hashes") or ""
    fields["ProcessName"] = _resolve_win_field(edata, "Image", "process.name") or ""


_WIN_FILLERS: dict[str, Callable[[dict, dict], None]] = {
    "AuthEvents": _fill_win_auth,
    "ProcessEvents": _fill_win_process,
    "NetworkEvents": _fill_win_network,
    "FileEvents": _fill_win_file,
}


def _win_extra(obj: dict, fields: dict, target: str) -> dict:
    """Top-level keys that are neither already mapped nor columns of the target table."""
    from siempl.schema import table_columns  # local import, as before: avoids a load-time cycle

    mapped_columns = {c[0] for c in table_columns(target)}
    return {k: v for k, v in obj.items() if k not in fields and k not in mapped_columns}


@register("windows_json")
def parse_windows_json(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse Windows event JSON (Winlogbeat / OTRF Security-Datasets style).

    Maps EventID to target tables:
      4624/4625 -> AuthEvents
      4688 -> ProcessEvents
      Sysmon 1 -> ProcessEvents
      Sysmon 3 -> NetworkEvents
      Sysmon 11 -> FileEvents
      others -> GenericEvents
    """
    if isinstance(raw, dict):
        obj = raw
    elif isinstance(raw, str):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return [_win_raw_fallback(raw, source_id)]
    else:
        return []
    if not isinstance(obj, dict):
        return []

    edata = _win_event_data(obj)
    event_id = _win_event_id(obj, edata)
    target = WIN_EVENT_TABLE.get(event_id, "GenericEvents")

    fields = _win_common_fields(obj, source_id, event_id)
    filler = _WIN_FILLERS.get(target)
    if filler is not None:
        filler(fields, edata)

    fields["Extra"] = _win_extra(obj, fields, target)
    if not fields.get("Message"):
        fields["Message"] = f"Windows EventID {event_id}"
    return [NormalizedEvent(table=target, fields=fields)]
