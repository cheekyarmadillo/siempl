"""Zeek JSON log parsers: conn.log and dns.log."""

from __future__ import annotations

import json
from typing import Any

from ._parsers_core import _as_dict, _parse_json_timestamp, _utcnow, register
from .types import NormalizedEvent

# ── Zeek parsers (optional) ───────────────────────────────────────────────────


@register("zeek_conn")
def parse_zeek_conn(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse Zeek connection log JSON -> NetworkEvents."""

    obj = _as_dict(raw)

    if not obj:
        return []

    ts = _utcnow()

    if "ts" in obj:
        dt = _parse_json_timestamp(obj["ts"])

        if dt:
            ts = dt

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "zeek_conn",
        "Message": f"{obj.get('id.orig_h', '')} -> {obj.get('id.resp_h', '')}:{obj.get('id.resp_p', '')} ({obj.get('proto', '')})",
        "RawEvent": json.dumps(obj, default=str),
        "SrcIp": obj.get("id.orig_h", ""),
        "DstIp": obj.get("id.resp_h", ""),
        "SrcPort": obj.get("id.orig_p"),
        "DstPort": obj.get("id.resp_p"),
        "Protocol": obj.get("proto", ""),
        "BytesIn": obj.get("resp_bytes", 0),
        "BytesOut": obj.get("orig_bytes", 0),
        "EventCode": "",
        "EventAction": "network_connect",
        "EventResult": "unknown",
    }

    return [NormalizedEvent(table="NetworkEvents", fields=fields)]


@register("zeek_dns")
def parse_zeek_dns(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse Zeek DNS log JSON -> NetworkEvents. HostName is the client (id.orig_h)."""

    obj = _as_dict(raw)

    if not obj:
        return []

    ts = _utcnow()

    if "ts" in obj:
        dt = _parse_json_timestamp(obj["ts"])

        if dt:
            ts = dt

    src_ip = obj.get("id.orig_h", "")

    fields = {
        "TimeGenerated": ts,
        "SourceId": source_id,
        "SourceType": "zeek_dns",
        "Message": f"DNS {obj.get('query', '')}",
        "RawEvent": json.dumps(obj, default=str),
        "HostName": src_ip,  # client that made the DNS query (for DGA rules 10, 20)
        "SrcIp": src_ip,
        "DstIp": obj.get("id.resp_h", ""),
        "DstPort": obj.get("id.resp_p"),
        "Protocol": "dns",
        "DnsQuery": obj.get("query", ""),
        "EventCode": "",
        "EventAction": "dns_query",
        "EventResult": "unknown",
    }

    return [NormalizedEvent(table="NetworkEvents", fields=fields)]
