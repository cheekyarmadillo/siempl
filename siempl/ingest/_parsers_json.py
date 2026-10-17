"""Generic JSON parser: known-field aliases, timestamp detection, JSON_ALIASES table."""

from __future__ import annotations

import json
from typing import Any

from ._parsers_core import _parse_json_timestamp, _utcnow, register
from .types import NormalizedEvent

# ── generic JSON parser ───────────────────────────────────────────────────────


# Heuristic JSON field aliasing: "alt_name" -> standard column name

JSON_ALIASES = {
    "@timestamp": "TimeGenerated",
    "timestamp": "TimeGenerated",
    "ts": "TimeGenerated",
    "time": "TimeGenerated",
    "datetime": "TimeGenerated",
    "source.ip": "SrcIp",
    "src_ip": "SrcIp",
    "src.ip": "SrcIp",
    "client_ip": "SrcIp",
    "client.ip": "SrcIp",
    "source_ip": "SrcIp",
    "srcaddr": "SrcIp",
    "destination.ip": "DstIp",
    "dst_ip": "DstIp",
    "dst.ip": "DstIp",
    "destination_ip": "DstIp",
    "dstaddr": "DstIp",
    "source.port": "SrcPort",
    "src_port": "SrcPort",
    "source_port": "SrcPort",
    "destination.port": "DstPort",
    "dst_port": "DstPort",
    "destination_port": "DstPort",
    "user": "UserName",
    "username": "UserName",
    "user.name": "UserName",
    "user_name": "UserName",
    "target_user": "TargetUserName",
    "target.username": "TargetUserName",
    "target_user_name": "TargetUserName",
    "hostname": "HostName",
    "host": "HostName",
    "host.name": "HostName",
    "computer": "HostName",
    "computer_name": "HostName",
    "process": "ProcessName",
    "process.name": "ProcessName",
    "process_name": "ProcessName",
    "image": "ProcessName",
    "command_line": "ProcessCmdLine",
    "cmdline": "ProcessCmdLine",
    "commandline": "ProcessCmdLine",
    "event_id": "EventCode",
    "event.code": "EventCode",
    "eventid": "EventCode",
    "event_id_num": "EventCode",
    "outcome": "EventResult",
    "result": "EventResult",
    "status": "EventResult",
    "message": "Message",
    "msg": "Message",
    "url": "Url",
    "uri": "Url",
    "request_url": "Url",
    "user_agent": "UserAgent",
    "agent": "UserAgent",
    "http_method": "HttpMethod",
    "method": "HttpMethod",
    "http_status": "StatusCode",
    "status_code": "StatusCode",
    "response_code": "StatusCode",
}


@register("generic_json")
def parse_generic_json(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse generic JSON with heuristic field aliasing. Never loses the RawEvent."""

    if isinstance(raw, dict):
        obj = raw

    elif isinstance(raw, str):
        try:
            obj = json.loads(raw)

        except json.JSONDecodeError:
            return [
                NormalizedEvent(
                    table="GenericEvents",
                    fields={
                        "TimeGenerated": _utcnow(),
                        "SourceId": source_id,
                        "SourceType": "generic_json",
                        "Message": str(raw)[:1000],
                        "RawEvent": str(raw),
                        "EventCode": "",
                        "EventAction": "",
                        "EventResult": "unknown",
                    },
                )
            ]

    else:
        return []

    if not isinstance(obj, dict):
        return []

    fields: dict[str, Any] = {
        "SourceId": source_id,
        "SourceType": "generic_json",
        "RawEvent": json.dumps(obj, default=str),
        "EventCode": "",
        "EventAction": "",
        "EventResult": "unknown",
    }

    # Walk the flat+first-level nested keys for aliasing

    flat: dict[str, Any] = {}

    for k, v in obj.items():
        if isinstance(v, dict):
            for sk, sv in v.items():
                flat[f"{k}.{sk}"] = sv

        flat[k] = v

    for key, val in flat.items():
        alias = JSON_ALIASES.get(key.lower())

        if alias:
            if alias == "TimeGenerated":
                dt = _parse_json_timestamp(val)

                if dt:
                    fields["TimeGenerated"] = dt

            elif alias not in fields:
                fields[alias] = val

    if "TimeGenerated" not in fields:
        fields["TimeGenerated"] = _utcnow()

    # Build Extra from everything not mapped

    mapped_keys = {k for k in fields}

    extra = {}

    for k, v in obj.items():
        if k not in mapped_keys:
            extra[k] = v

    if "Message" not in fields:
        # Use first string-like field as message

        for k, v in obj.items():
            if isinstance(v, str) and len(v) < 500:
                fields["Message"] = v

                break

        fields.setdefault("Message", "")

    fields["Extra"] = extra

    return [NormalizedEvent(table="GenericEvents", fields=fields)]
