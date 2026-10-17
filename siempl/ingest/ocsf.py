"""OCSF (Open Cybersecurity Schema Framework) event parser.

Spec: https://schema.ocsf.io (v1.x). One OCSF event = one JSON object carrying `class_uid`,
`category_uid`, `activity_id`, `time` (epoch ms), `severity_id`, `status_id`, `metadata`, plus
class-specific objects (`actor`, `src_endpoint`, `dst_endpoint`, `process`, `file`, `http_request`...).

Routing (class_uid -> table):
  1001 File System Activity ............ FileEvents
  1007 Process Activity ................ ProcessEvents
  3001 Account Change, 3002 Authentication, 3003 Authorize Session,
  3004 Entity Management ............... AuthEvents
  4001 Network Activity, 4003 DNS ...... NetworkEvents  (4005/4007/... connection-ish classes too)
  4002 HTTP Activity ................... WebAccess
  everything else (findings, API activity, inventory, email, ...) -> GenericEvents

Everything we do not map into a column is kept in Extra (class_uid, class_name, category_uid,
type_uid, severity_id, metadata, enrichments, unmapped, and any other top-level keys) so no
information is lost and Sigma/KQL can still reach it via Extra.

Registered as parser "ocsf"; auto-detected by auto_parse() for JSON objects with class_uid + category_uid.
Also accepts a JSON array of events (returns one NormalizedEvent per element).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .parsers import _utcnow, register
from .types import NormalizedEvent

# class_uid -> table
CLASS_TABLE: dict[int, str] = {
    1001: "FileEvents", 1007: "ProcessEvents",
    3001: "AuthEvents", 3002: "AuthEvents", 3003: "AuthEvents", 3004: "AuthEvents",
    4001: "NetworkEvents", 4003: "NetworkEvents", 4005: "NetworkEvents", 4006: "NetworkEvents",
    4007: "NetworkEvents", 4002: "WebAccess",
}

# category_uid fallback when class_uid is unknown
CATEGORY_TABLE: dict[int, str] = {1: "FileEvents", 3: "AuthEvents", 4: "NetworkEvents"}

ACTIVITY: dict[int, dict[int, str]] = {
    1001: {1: "file_create", 2: "file_read", 3: "file_update", 4: "file_delete", 5: "file_rename",
           6: "file_set_attributes", 7: "file_set_security", 8: "file_get_attributes", 9: "file_mount"},
    1007: {1: "process_start", 2: "process_terminate", 3: "process_open", 4: "process_inject", 5: "process_set_user"},
    3001: {1: "account_create", 2: "account_enable", 3: "password_change", 4: "password_reset", 5: "account_disable",
           6: "account_delete", 7: "mfa_enable", 8: "mfa_disable", 9: "account_lock"},
    3002: {1: "login", 2: "logoff", 3: "auth_ticket", 4: "service_ticket", 5: "preauth"},
    3003: {1: "assign_privileges", 2: "assign_groups"},
    4001: {1: "connect", 2: "close", 3: "reset", 4: "fail", 5: "refuse", 6: "traffic", 7: "listen"},
    4002: {1: "request", 2: "request", 3: "request", 4: "request", 5: "request", 6: "request", 7: "request"},
    4003: {1: "dns_query", 2: "dns_response", 6: "dns_traffic"},
}

STATUS_RESULT = {1: "success", 2: "failure"}
SEVERITY_NAMES = {0: "unknown", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical", 6: "fatal"}

# top-level keys we consume into columns (everything else goes to Extra)
_CONSUMED = {
    "time", "start_time", "end_time", "message", "activity_id", "activity_name", "status_id", "status",
    "status_code", "status_detail", "device", "src_endpoint", "dst_endpoint", "actor", "user", "process",
    "file", "http_request", "http_response", "traffic", "connection_info", "query", "src_user", "dst_user",
    "logon_type", "logon_type_id", "auth_protocol", "auth_protocol_id", "raw_data",
}


def _g(d: Any, *path: str, default: Any = None) -> Any:
    """Safe nested get."""
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
        if cur is None:
            return default
    return cur


def _to_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _to_dt(v: Any) -> datetime:
    """OCSF timestamp_t is epoch milliseconds; tolerate seconds and ISO-8601."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        secs = v / 1000.0 if v > 1e11 else float(v)
        try:
            return datetime.fromtimestamp(secs, tz=UTC).replace(tzinfo=None)
        except (OverflowError, OSError, ValueError):
            return _utcnow()
    if isinstance(v, str) and v:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            try:
                return _to_dt(float(v))
            except ValueError:
                return _utcnow()
    return _utcnow()


def _hash(file_obj: Any) -> str | None:
    """Prefer sha256, then sha1, md5, any."""
    hashes = _g(file_obj, "hashes") or []
    best = None
    rank = {"sha-256": 0, "sha256": 0, "sha-1": 1, "sha1": 1, "md5": 2}
    for h in hashes if isinstance(hashes, list) else []:
        if not isinstance(h, dict):
            continue
        alg = str(h.get("algorithm") or "").lower()
        val = h.get("value")
        if val and (best is None or rank.get(alg, 9) < best[0]):
            best = (rank.get(alg, 9), val)
    return best[1] if best else None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return str(path).replace("\\", "/").rsplit("/", 1)[-1] or None


def _first_ip(ep: Any) -> str | None:
    ip = _g(ep, "ip")
    if ip:
        return str(ip)
    return None


def _host(obj: dict) -> str | None:
    for path in (("device", "hostname"), ("device", "name"), ("src_endpoint", "hostname"), ("src_endpoint", "name")):
        v = _g(obj, *path)
        if v:
            return str(v)
    return None


def _user(obj: dict) -> str | None:
    for path in (("actor", "user", "name"), ("user", "name"), ("src_user", "name"), ("actor", "user", "uid")):
        v = _g(obj, *path)
        if v:
            return str(v)
    return None


def _result(obj: dict) -> str:
    sid = _to_int(obj.get("status_id"))
    if sid in STATUS_RESULT:
        return STATUS_RESULT[sid]
    st = str(obj.get("status") or "").lower()
    if st in ("success", "succeeded", "ok", "allowed"):
        return "success"
    if st in ("failure", "failed", "fail", "denied", "blocked"):
        return "failure"
    return "unknown"


def _action(class_uid: int | None, obj: dict) -> str:
    name = obj.get("activity_name")
    aid = _to_int(obj.get("activity_id"))
    mapped = ACTIVITY.get(class_uid or -1, {}).get(aid if aid is not None else -1)
    if mapped:
        return mapped
    if name:
        return str(name).strip().lower().replace(" ", "_")
    return ""


def _extra(obj: dict, class_uid: int | None) -> dict:
    extra = {k: v for k, v in obj.items() if k not in _CONSUMED}
    # keep consumed objects that carry fields we do not map to columns
    for k in ("actor", "device", "http_request", "http_response", "src_endpoint", "dst_endpoint", "file", "process"):
        if isinstance(obj.get(k), dict):
            extra[k] = obj[k]
    sev = _to_int(obj.get("severity_id"))
    if sev is not None:
        extra["severity"] = SEVERITY_NAMES.get(sev, str(sev))
    for k in ("logon_type", "logon_type_id", "auth_protocol", "status_code", "status_detail"):
        if obj.get(k) is not None:
            extra[k] = obj[k]
    return extra


def _process_fields(proc: Any) -> dict:
    out: dict = {}
    if not isinstance(proc, dict):
        return out
    path = _g(proc, "file", "path") or _g(proc, "file", "name")
    name = _g(proc, "name") or _g(proc, "file", "name") or _basename(path)
    if name:
        out["ProcessName"] = str(name)
    if _g(proc, "cmd_line"):
        out["ProcessCmdLine"] = str(proc["cmd_line"])
    if path:
        out["ProcessPath"] = str(path)
    if _to_int(proc.get("pid")) is not None:
        out["ProcessId"] = _to_int(proc.get("pid"))
    h = _hash(proc.get("file"))
    if h:
        out["FileHash"] = h
    return out


def _copy_present(dst: dict, src: dict, keys: tuple[str, ...]) -> None:
    """Copy each key that is present in src into dst (same key name)."""
    for key in keys:
        if key in src:
            dst[key] = src[key]


_PARENT_PROCESS_KEYS = (
    ("ProcessName", "ParentProcessName"),
    ("ProcessId", "ParentProcessId"),
    ("ProcessCmdLine", "ParentCmdLine"),
)
_FILE_PROCESS_KEYS = ("ProcessName", "ProcessCmdLine", "ProcessPath", "ProcessId")
_NETWORK_PROCESS_KEYS = ("ProcessPath", "ProcessId", "ProcessName", "ProcessCmdLine")
_GENERIC_PROCESS_KEYS = ("ProcessName", "ProcessCmdLine")
_DIRECTION_NAMES = {"1": "inbound", "2": "outbound", "3": "lateral"}


def _process_context(obj: dict, class_uid: int | None) -> tuple[Any, dict]:
    """Process context: for Process Activity `process` is the subject; otherwise the actor's process."""
    proc = obj.get("process") if class_uid == 1007 else (_g(obj, "actor", "process") or obj.get("process"))
    return proc, _process_fields(proc)


def _base_fields(obj: dict, source_id: str, raw_text: str, class_uid: int | None) -> dict:
    """Columns every OCSF event gets, in the order they are emitted."""
    src, dst = obj.get("src_endpoint"), obj.get("dst_endpoint")
    return {
        "TimeGenerated": _to_dt(obj.get("time") if obj.get("time") is not None else obj.get("start_time")),
        "SourceId": source_id, "SourceType": "ocsf",
        "EventCode": str(class_uid) if class_uid is not None else "",
        "EventAction": _action(class_uid, obj),
        "EventResult": _result(obj),
        "HostName": _host(obj), "UserName": _user(obj),
        "SrcIp": _first_ip(src), "DstIp": _first_ip(dst),
        "SrcPort": _to_int(_g(src, "port")), "DstPort": _to_int(_g(dst, "port")),
        "Message": str(obj.get("message") or obj.get("activity_name") or _g(obj, "metadata", "event_code") or ""),
        "RawEvent": raw_text,
    }


def _fill_parent_process(fields: dict, proc: Any) -> None:
    parent = _g(proc, "parent_process") or {}
    if not parent:
        return
    ppf = _process_fields(parent)
    for src_key, dst_key in _PARENT_PROCESS_KEYS:
        if src_key in ppf:
            fields[dst_key] = ppf[src_key]


def _fill_process(fields: dict, obj: dict, pf: dict, proc: Any) -> None:
    fields.update(pf)
    _fill_parent_process(fields, proc)
    integ = _g(proc, "integrity")
    if integ:
        fields["IntegrityLevel"] = str(integ)
    if not fields.get("UserName"):
        u = _g(proc, "user", "name")
        if u:
            fields["UserName"] = str(u)


def _fill_file(fields: dict, obj: dict, pf: dict, proc: Any) -> None:
    f = obj.get("file") or {}
    path = _g(f, "path") or _g(f, "name")
    if path:
        fields["FilePath"] = str(path)
    fname = _g(f, "name") or _basename(path)
    if fname:
        fields["FileName"] = str(fname)
    h = _hash(f)
    if h:
        fields["FileHash"] = h
    fields["Operation"] = fields["EventAction"]
    _copy_present(fields, pf, _FILE_PROCESS_KEYS)


def _fill_auth_logon(fields: dict, obj: dict) -> None:
    dst_user = _g(obj, "dst_user", "name") or _g(obj, "user", "name")
    if dst_user:
        fields["TargetUserName"] = str(dst_user)
    lt = obj.get("logon_type") or obj.get("logon_type_id")
    if lt is not None:
        fields["LogonType"] = str(lt)
    ap = obj.get("auth_protocol") or obj.get("auth_protocol_id")
    if ap is not None:
        fields["AuthMethod"] = str(ap)


def _fill_auth_failure(fields: dict, obj: dict) -> None:
    if fields["EventResult"] == "failure":
        fr = obj.get("status_detail") or obj.get("status_code") or obj.get("status")
        if fr:
            fields["FailureReason"] = str(fr)


def _fill_auth(fields: dict, obj: dict, pf: dict, proc: Any) -> None:
    _fill_auth_logon(fields, obj)
    _fill_auth_failure(fields, obj)


def _fill_connection(fields: dict, obj: dict) -> None:
    ci = obj.get("connection_info") or {}
    proto = _g(ci, "protocol_name") or _g(ci, "protocol_num")
    if proto is not None:
        fields["Protocol"] = str(proto).lower()
    direction = _g(ci, "direction") or _g(ci, "direction_id")
    if direction is not None:
        d = str(direction).lower()
        fields["Direction"] = _DIRECTION_NAMES.get(d, d)
    bi, bo = _to_int(_g(obj, "traffic", "bytes_in")), _to_int(_g(obj, "traffic", "bytes_out"))
    if bi is not None:
        fields["BytesIn"] = bi
    if bo is not None:
        fields["BytesOut"] = bo


def _fill_domain(fields: dict, obj: dict) -> None:
    q = _g(obj, "query", "hostname")
    if q:
        fields["DnsQuery"] = str(q)
        fields["Domain"] = str(q)
    dhost = _g(obj, "dst_endpoint", "hostname")
    if dhost and "Domain" not in fields:
        fields["Domain"] = str(dhost)


def _fill_network(fields: dict, obj: dict, pf: dict, proc: Any) -> None:
    _fill_connection(fields, obj)
    _fill_domain(fields, obj)
    _copy_present(fields, pf, _NETWORK_PROCESS_KEYS)


def _fill_web_request(fields: dict, obj: dict) -> None:
    req = obj.get("http_request") or {}
    fields["HttpMethod"] = str(_g(req, "http_method") or "").upper() or None
    url = _g(req, "url", "url_string") or _g(req, "url", "path")
    if url:
        fields["Url"] = str(url)
    path = _g(req, "url", "path")
    if path:
        fields["UrlPath"] = str(path)
    if _g(req, "user_agent"):
        fields["UserAgent"] = str(req["user_agent"])
    if _g(req, "referrer"):
        fields["Referrer"] = str(req["referrer"])


def _fill_web_response(fields: dict, obj: dict) -> None:
    resp = obj.get("http_response") or {}
    code = _to_int(_g(resp, "code"))
    if code is not None:
        fields["StatusCode"] = code
    b = _to_int(_g(resp, "length")) or _to_int(_g(obj, "traffic", "bytes_out"))
    if b is not None:
        fields["Bytes"] = b


def _fill_web(fields: dict, obj: dict, pf: dict, proc: Any) -> None:
    _fill_web_request(fields, obj)
    _fill_web_response(fields, obj)
    if not fields.get("EventAction"):
        fields["EventAction"] = "request"


def _fill_generic(fields: dict, obj: dict, pf: dict, proc: Any) -> None:
    """Generic table: still surface process context if present."""
    _copy_present(fields, pf, _GENERIC_PROCESS_KEYS)


_TABLE_FILLERS: dict[str, Callable[[dict, dict, dict, Any], None]] = {
    "ProcessEvents": _fill_process,
    "FileEvents": _fill_file,
    "AuthEvents": _fill_auth,
    "NetworkEvents": _fill_network,
    "WebAccess": _fill_web,
}


def _one(obj: dict, source_id: str, raw_text: str) -> NormalizedEvent:
    class_uid = _to_int(obj.get("class_uid"))
    cat_uid = _to_int(obj.get("category_uid"))
    table = CLASS_TABLE.get(class_uid or -1) or CATEGORY_TABLE.get(cat_uid or -1) or "GenericEvents"

    fields = _base_fields(obj, source_id, raw_text, class_uid)
    proc, pf = _process_context(obj, class_uid)
    _TABLE_FILLERS.get(table, _fill_generic)(fields, obj, pf, proc)

    fields["Extra"] = _extra(obj, class_uid)
    fields = {k: v for k, v in fields.items() if v is not None}
    return NormalizedEvent(table=table, fields=fields)


def looks_like_ocsf(obj: Any) -> bool:
    return (isinstance(obj, dict) and "class_uid" in obj
            and ("category_uid" in obj or "activity_id" in obj or "metadata" in obj))


@register("ocsf")
def parse_ocsf(raw: Any, source_id: str) -> list[NormalizedEvent]:
    """Parse OCSF JSON events (class_uid routing; unmapped attributes preserved in Extra)."""
    obj = raw
    raw_text = raw if isinstance(raw, str) else json.dumps(raw, default=str)
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            return [NormalizedEvent(table="GenericEvents", fields={
                "TimeGenerated": _utcnow(), "SourceId": source_id, "SourceType": "ocsf",
                "Message": raw[:1000], "RawEvent": raw, "EventCode": "", "EventAction": "",
                "EventResult": "unknown"})]
    items = obj if isinstance(obj, list) else [obj]
    out: list[NormalizedEvent] = []
    for it in items:
        if isinstance(it, dict):
            out.append(_one(it, source_id, json.dumps(it, default=str) if isinstance(obj, list) else raw_text))
    return out
