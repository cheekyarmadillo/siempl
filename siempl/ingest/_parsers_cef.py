"""ArcSight CEF (Common Event Format) parser."""

from __future__ import annotations

from datetime import datetime

from ._parsers_core import _parse_json_timestamp, _utcnow, register
from .types import NormalizedEvent

# -- CEF parser --


# ArcSight CEF extension dictionary -- standard keys and our column mapping.

_CEF_EXTENSION_MAP = {
    "src": "SrcIp",
    "source": "SrcIp",
    "saddr": "SrcIp",
    "suser": "UserName",
    "shost": "HostName",
    "spt": "SrcPort",
    "sourcePort": "SrcPort",
    "dst": "DstIp",
    "destination": "DstIp",
    "daddr": "DstIp",
    "duser": "TargetUserName",
    "dhost": "HostName",
    "dpt": "DstPort",
    "destinationPort": "DstPort",
    "dstPort": "DstPort",
    "proto": "Protocol",
    "protocol": "Protocol",
    "in": "BytesIn",
    "out": "BytesOut",
    "cs3": "Direction",
    "deviceEventClassId": "EventCode",
    "deviceEventClassID": "EventCode",
    "act": "EventAction",
    "outcome": "EventResult",
    "msg": "Message",
    "request": "Url",
    "requestUrl": "Url",
    "requestURL": "Url",
    "requestMethod": "HttpMethod",
    "requestClientApplication": "UserAgent",
    "fname": "FilePath",
    "fileName": "FileName",
    "fileHash": "FileHash",
    "cs1": "ExtraCs1",
    "cs2": "ExtraCs2",
    "rt": "TimeGenerated",
    "start": "TimeGenerated",
    "end": "TimeGeneratedEnd",
    "cs4": "ExtraCs4",
    "cs5": "ExtraCs5",
    "cs6": "ExtraCs6",
}


def _cef_unescape(val):

    return (
        val.replace("\\\\", "\x00")
        .replace("\\=", "=")
        .replace("\\|", "|")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\x00", "\\\\")
    )


def _cef_parse_timestamp(val):

    val = val.strip()

    try:
        n = int(val)

        if 1e12 < n < 1e15:
            return datetime.fromtimestamp(n / 1000.0).replace(tzinfo=None)

        if 1e9 < n < 1e12:
            return datetime.fromtimestamp(n).replace(tzinfo=None)

    except (ValueError, OverflowError):
        pass

    dt = _parse_json_timestamp(val)

    if dt:
        return dt

    return None


def _cef_target_table(fields, extra):

    has_net = bool(fields.get("SrcIp") and fields.get("DstIp"))

    has_ports = fields.get("SrcPort") is not None or fields.get("DstPort") is not None

    if has_net and (has_ports or fields.get("Protocol")):
        return "NetworkEvents"

    if fields.get("FilePath") or fields.get("FileName") or fields.get("FileHash"):
        return "FileEvents"

    if fields.get("UserName") or fields.get("TargetUserName"):
        if fields.get("SrcIp"):
            return "AuthEvents"

    if fields.get("Url") or fields.get("HttpMethod") or fields.get("UserAgent"):
        return "WebAccess"

    return "GenericEvents"


def _cef_fallback_event(msg: str, original: str, source_id: str, now: datetime) -> list[NormalizedEvent]:
    """Input that is not a usable CEF record: keep the whole text as Message in GenericEvents."""
    return [
        NormalizedEvent(
            table="GenericEvents",
            fields={
                "TimeGenerated": now,
                "SourceId": source_id,
                "SourceType": "cef",
                "Message": msg,
                "RawEvent": original,
                "EventCode": "",
                "EventAction": "",
                "EventResult": "unknown",
            },
        )
    ]


def _cef_header_end(msg: str) -> int:
    """Index of the 7th unescaped pipe that closes the header, or -1 if there are fewer than 7."""
    pipe_count = 0
    for i, ch in enumerate(msg):
        if ch == "|" and (i == 0 or msg[i - 1] != "\\\\"):
            pipe_count += 1
            if pipe_count == 7:
                return i
    return -1


def _cef_part(parts: list[str], index: int) -> str:
    return parts[index] if len(parts) > index else ""


def _cef_header_fields(header: str, now: datetime, source_id: str, original: str) -> dict:
    """Columns from the 7 header parts (CEF:v|vendor|product|version|sigId|name|severity)."""
    parts = header.split("|")
    fields = {
        "TimeGenerated": now,
        "SourceId": source_id,
        "SourceType": "cef",
        "EventCode": _cef_part(parts, 4),
        "EventAction": _cef_part(parts, 5),
        "Message": _cef_part(parts, 5),
        "RawEvent": original,
        "DeviceVendor": _cef_part(parts, 1),
        "DeviceProduct": _cef_part(parts, 2),
        "DeviceVersion": _cef_part(parts, 3),
    }
    severity = _cef_part(parts, 6)
    sev_clean = severity.split(" ")[0] if severity else ""
    if sev_clean:
        try:
            fields["SeverityLevel"] = int(sev_clean)
        except (ValueError, TypeError):
            pass
    return fields


def _cef_skip_spaces(text: str, i: int) -> int:
    while i < len(text) and text[i] == " ":
        i += 1
    return i


def _cef_starts_key(ch: str) -> bool:
    return ch.isalpha() or ch == "_" or ch.isdigit() or ch == "."


def _cef_is_key_boundary(ext: str, j: int) -> bool:
    """True if the space at j starts the next ' key=' pair (so the current value ends before it)."""
    if ext[j] != " ":
        return False
    if j + 1 < len(ext) and not _cef_starts_key(ext[j + 1]):
        return False
    ns = ext.find("=", j + 1)
    if ns < 0:
        return False
    potential_key = ext[j + 1 : ns].strip()
    return (
        bool(potential_key)
        and " " not in potential_key
        and potential_key[0].replace("_", "").replace(".", "").isalnum()
    )


def _cef_value_end(ext: str, start: int) -> int:
    """End index (exclusive) of a raw extension value that begins at start."""
    j = start
    while j < len(ext):
        if _cef_is_key_boundary(ext, j):
            break
        j += 1
    return j


def _cef_iter_extensions(ext: str):
    """Yield (raw_key, raw_value) pairs of a CEF extension string, in order. Values are not unescaped."""
    i = 0
    while True:
        i = _cef_skip_spaces(ext, i)
        if i >= len(ext):
            return
        eq_idx = ext.find("=", i)
        if eq_idx < 0:
            return
        j = _cef_value_end(ext, eq_idx + 1)
        yield ext[i:eq_idx].strip(), ext[eq_idx + 1 : j]
        i = j


def _cef_apply_extension(fields: dict, extra: dict, key: str, value: str) -> None:
    mapped = _CEF_EXTENSION_MAP.get(key)
    if mapped == "TimeGenerated":
        dt = _cef_parse_timestamp(value)
        if dt:
            fields["TimeGenerated"] = dt
    elif mapped in ("SrcPort", "DstPort"):
        try:
            fields[mapped] = int(value)
        except (ValueError, TypeError):
            fields[mapped] = value
    elif mapped:
        fields[mapped] = value
    else:
        extra[key] = value


def _cef_fold_custom_label(fields: dict, extra: dict, n: int) -> None:
    """cs<n>=value with cs<n>Label=name: a 'Direction' label goes to Direction, others to Extra[name]."""
    label_val = extra.pop(f"cs{n}Label", None)
    raw_val = fields.pop(f"ExtraCs{n}", None)
    if label_val and label_val in ("Direction", "direction"):
        fields["Direction"] = raw_val or ""
    elif label_val:
        extra[label_val] = raw_val
    elif raw_val is not None:
        extra[f"cs{n}"] = raw_val


def _cef_fill_event_code(fields: dict, extra: dict) -> None:
    if not fields.get("EventCode"):
        # deviceEventClassID is consumed here even when deviceEventClassId is present (existing behavior)
        legacy = extra.pop("deviceEventClassID", "")
        fields["EventCode"] = extra.pop("deviceEventClassId", legacy)


def _cef_normalize_outcome(fields: dict, extra: dict) -> None:
    outcome = extra.pop("outcome", None) or fields.get("EventResult", "")
    if outcome:
        o = outcome.lower()
        fields["EventResult"] = (
            "success"
            if o in ("success", "allow", "permitted", "allowed")
            else "failure"
            if o in ("failure", "fail", "deny", "denied", "block", "blocked", "reject", "rejected")
            else "unknown"
        )


def _cef_fold_custom_labels(fields: dict, extra: dict) -> None:
    for n in range(1, 8):
        _cef_fold_custom_label(fields, extra, n)


@register("cef")
def parse_cef(raw, source_id):
    msg = raw if isinstance(raw, str) else str(raw)
    original = msg
    now = _utcnow()

    if not msg.startswith("CEF:"):
        return _cef_fallback_event(msg, original, source_id, now)
    header_end = _cef_header_end(msg)
    if header_end < 0:
        return _cef_fallback_event(msg, original, source_id, now)

    fields = _cef_header_fields(msg[:header_end], now, source_id, original)
    extra: dict = {}
    for key, raw_value in _cef_iter_extensions(msg[header_end + 1 :]):
        _cef_apply_extension(fields, extra, key, _cef_unescape(raw_value))

    _cef_fold_custom_labels(fields, extra)
    _cef_fill_event_code(fields, extra)
    _cef_normalize_outcome(fields, extra)

    target = _cef_target_table(fields, extra)
    fields["Extra"] = extra
    return [NormalizedEvent(table=target, fields=fields)]
