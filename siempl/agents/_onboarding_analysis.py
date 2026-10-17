"""Pure sample-analysis helpers for OnboardingAgent (no agent or DB-write state).

Moved out of onboarding.py to keep that module under its size ratchet. Behavior is unchanged.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from collections import Counter
from typing import Any

from ..db import Database
from ..ingest.mapping import MappingParser, validate_spec
from ..ingest.parsers import auto_parse
from ..schema import DATA_TABLES
from ._onboarding_delim import delimited_pairs, detect_kv_delimiter

# Logger name kept as the original module's so log records and filters are unchanged.
logger = logging.getLogger("siempl.agents.onboarding")


# ── helper: collect raw samples ────────────────────────────────────────────────

def _collect_samples(db: Database, source_id: str, samples: list | None = None) -> list[str]:
    """Collect raw event samples for a source. Returns list of raw strings."""
    if samples:
        return [s if isinstance(s, str) else json.dumps(s) for s in samples[:100]]

    rows = db.query(
        'SELECT "RawEvent" FROM "GenericEvents" WHERE "SourceId"=? ORDER BY "TimeGenerated" DESC LIMIT 100',
        [source_id])
    raw = [r["RawEvent"] for r in rows if r.get("RawEvent")]
    if len(raw) < 5:
        # Also try other tables
        for table in DATA_TABLES:
            if table == "GenericEvents":
                continue
            try:
                more = db.query(
                    f'SELECT "RawEvent" FROM "{table}" WHERE "SourceId"=? ORDER BY "TimeGenerated" DESC LIMIT 50',
                    [source_id])
                for r in more:
                    if r.get("RawEvent") and r["RawEvent"] not in raw:
                        raw.append(r["RawEvent"])
            except Exception:
                logger.debug("_collect_samples: ignored error", exc_info=True)
    return raw[:100]


# ── helper: auto-detect existing parser ────────────────────────────────────────

def _detect_parser(samples: list[str], source_id: str) -> dict[str, Any]:
    """Run auto_parse on each sample and tally which parser fires.
    Returns {"parser": name|None, "hits": int, "total": int, "table": str|None}
    """
    hits: Counter[str] = Counter()
    tables: Counter[str] = Counter()

    for s in samples:
        try:
            events = auto_parse(s, source_id)
            if events:
                # The parser name is embedded in SourceType
                st = events[0].fields.get("SourceType", "generic_json")
                tbl = events[0].table
                # Heuristic: if source_type is not "unknown" and table is not just GenericEvents with no fields
                if st not in ("unknown",) or tbl != "GenericEvents":
                    hits[st] += 1
                tables[tbl] += 1
        except Exception:
            logger.debug("_detect_parser: ignored error", exc_info=True)

    if hits:
        best = hits.most_common(1)[0]
        return {"parser": best[0], "hits": best[1], "total": len(samples),
                "table": tables.most_common(1)[0][0] if tables else None,
                "all_hits": dict(hits)}
    return {"parser": None, "hits": 0, "total": len(samples), "table": None, "all_hits": {}}


# ── helper: analyze sample structure ───────────────────────────────────────────

def _parse_json_sample(s: str, all_json_keys: Counter, field_examples: dict) -> bool:
    try:
        obj = json.loads(s)
        if isinstance(obj, dict):
            for k, v in obj.items():
                all_json_keys[k] += 1
                _add_field_example(field_examples, k, str(v)[:100])
            return True
    except (json.JSONDecodeError, ValueError):
        pass
    return False


def _parse_csv_sample(s: str, all_keys: Counter, field_examples: dict) -> bool:
    try:
        reader = csv.reader(io.StringIO(s))
        row = next(reader, None)
        if row and len(row) >= 2:
            for i, v in enumerate(row):
                k = f"col{i+1}"
                all_keys[k] += 1
                _add_field_example(field_examples, k, str(v)[:100])
            return True
    except Exception:
        logger.debug("_analyze_samples: ignored error", exc_info=True)
    return False


def _parse_kv_sample(s: str, all_keys: Counter, field_examples: dict, delimiter: str | None = None) -> bool:
    if delimiter:
        kv_pairs = delimited_pairs(s, delimiter)
    else:
        kv_pairs = re.findall(r'(\S+)=("[^"]*"|\'[^\']*\'|\S+)', s)
    if len(kv_pairs) >= 2:
        for k, v in kv_pairs:
            all_keys[k] += 1
            _add_field_example(field_examples, k, str(v)[:100])
        return True
    return False


def _add_field_example(field_examples: dict, key: str, value: str) -> None:
    if key not in field_examples:
        field_examples[key] = []
    if len(field_examples[key]) < 3:
        field_examples[key].append(value)


def _extract_regex_patterns(samples: list[str], all_keys: Counter) -> None:
    for s in samples[:5]:
        ip_pattern = re.findall(r'\d+\.\d+\.\d+\.\d+', s)
        for _ in ip_pattern:
            all_keys["ip"] += 1
        if re.search(r'\d{2}:\d{2}:\d{2}', s):
            all_keys["timestamp"] += 1


def _kv_delimiter_entry(fmt: str, delimiter: str | None) -> dict:
    """{'kv_delimiter': d} only for delimited-kv samples, so other analyses keep their exact shape."""
    return {"kv_delimiter": delimiter} if fmt == "kv" and delimiter else {}


def _analyze_samples(samples: list[str]) -> dict[str, Any]:
    """Analyze structure of raw samples to guide mapping spec generation.

    Returns {"format": "json"|"csv"|"kv"|"regex"|"unknown", "fields": {...}, "stats": {}}
    """
    if not samples:
        return {"format": "unknown", "fields": {}, "stats": {}}

    json_count = 0
    csv_count = 0
    kv_count = 0
    all_keys: Counter[str] = Counter()
    all_json_keys: Counter[str] = Counter()
    field_examples: dict[str, list] = {}
    delimiter = detect_kv_delimiter(samples)

    for s in samples[:50]:
        s = s.strip()
        if not s:
            continue
        if _parse_json_sample(s, all_json_keys, field_examples):
            json_count += 1
            continue
        if _parse_csv_sample(s, all_keys, field_examples):
            csv_count += 1
            continue
        if _parse_kv_sample(s, all_keys, field_examples, delimiter):
            kv_count += 1
            continue

    counts = {"json": json_count, "csv": csv_count, "kv": kv_count}
    best_fmt = max(counts, key=counts.get) if max(counts.values()) > 0 else "regex"

    if best_fmt == "regex":
        _extract_regex_patterns(samples, all_keys)

    return {
        "format": best_fmt,
        "json_keys": dict(all_json_keys.most_common(20)),
        "keys": dict(all_keys.most_common(20)),
        "field_examples": {k: v for k, v in list(field_examples.items())[:20]},
        "counts": counts,
        "total": len(samples),
        **_kv_delimiter_entry(best_fmt, delimiter),
    }


# ── helper: heuristic mapping spec proposal ────────────────────────────────────

# Known field name -> column name aliases (extends JSON_ALIASES from parsers.py)
FIELD_ALIASES: dict[str, str] = {
    # Lowercased sample field name -> schema column name
    "timestamp": "TimeGenerated", "@timestamp": "TimeGenerated",
    "time": "TimeGenerated", "ts": "TimeGenerated", "datetime": "TimeGenerated",
    "date": "TimeGenerated", "log_time": "TimeGenerated",
    "src_ip": "SrcIp", "source_ip": "SrcIp", "srcip": "SrcIp",
    "client_ip": "SrcIp", "clientip": "SrcIp", "src": "SrcIp",
    "srcaddr": "SrcIp", "source.address": "SrcIp", "src_addr": "SrcIp",
    "dst_ip": "DstIp", "dest_ip": "DstIp", "dstip": "DstIp",
    "dest": "DstIp", "dstaddr": "DstIp", "destination.ip": "DstIp",
    "src_port": "SrcPort", "source_port": "SrcPort", "sport": "SrcPort",
    "dst_port": "DstPort", "dest_port": "DstPort", "dport": "DstPort",
    "username": "UserName", "user": "UserName", "user_name": "UserName",
    "login": "UserName", "account": "UserName",
    "target_user": "TargetUserName", "target_username": "TargetUserName",
    "hostname": "HostName", "host": "HostName", "host_name": "HostName",
    "computer": "HostName", "server": "HostName", "machine": "HostName",
    "process": "ProcessName", "process_name": "ProcessName",
    "image": "ProcessName", "exe": "ProcessName",
    "cmdline": "ProcessCmdLine", "command": "ProcessCmdLine",
    "command_line": "ProcessCmdLine",
    "event_id": "EventCode", "eventid": "EventCode", "code": "EventCode",
    "event_code": "EventCode", "id": "EventCode",
    "status": "EventResult", "result": "EventResult", "outcome": "EventResult",
    "action": "EventAction", "event_type": "EventAction",
    "dev": "HostName", "device": "HostName", "evt": "EventCode",
    "message": "Message", "msg": "Message", "description": "Message",
    "log": "Message", "text": "Message",
    "ip": "SrcIp", "ip_address": "SrcIp",
    "url": "Url", "uri": "Url", "request_url": "Url", "path": "UrlPath",
    "user_agent": "UserAgent", "ua": "UserAgent",
    "method": "HttpMethod", "http_method": "HttpMethod",
    "status_code": "StatusCode", "response_code": "StatusCode",
    "http_status": "StatusCode",
    "severity": "SeverityLevel",
    "protocol": "Protocol",
    "port": "DstPort",
    "file": "FileName", "filename": "FileName", "file_name": "FileName",
    "file_path": "FilePath", "path_full": "FilePath",
    "hash": "FileHash", "sha256": "FileHash", "md5": "FileHash",
    "domain": "Domain", "dns_query": "DnsQuery", "query": "DnsQuery",
    "referrer": "Referrer", "referer": "Referrer",
    "bytes": "Bytes", "size": "Bytes",
    "logontype": "LogonType", "logon_type": "LogonType",
    "auth_method": "AuthMethod", "authmethod": "AuthMethod",
    "failure_reason": "FailureReason", "reason": "FailureReason",
    "error": "FailureReason",
}

# Heuristic table selection based on fields present
TABLE_HINTS: dict[str, list[str]] = {
    "AuthEvents": ["username", "user", "auth_method", "logon_type", "target_user",
                   "failure_reason", "auth", "login", "password", "session"],
    "ProcessEvents": ["process", "process_name", "cmdline", "command_line", "image",
                      "parent_process", "process_id", "pid", "integrity"],
    "NetworkEvents": ["protocol", "src_port", "dst_port", "dns_query", "domain",
                      "bytes_in", "bytes_out", "direction"],
    "WebAccess": ["url", "uri", "http_method", "user_agent", "status_code",
                  "referrer", "method", "response"],
    "FileEvents": ["file", "file_name", "file_path", "file_hash", "hash", "operation"],
    "Syslog": ["facility", "app_name", "severity", "syslog"],
}


def _guess_target_table(field_keys: list[str]) -> str:
    """Guess the best target table from detected field names."""
    keys_lower = [k.lower() for k in field_keys]
    scores: dict[str, int] = {}

    for table, hints in TABLE_HINTS.items():
        score = 0
        for hint in hints:
            for k in keys_lower:
                if hint in k or k in hint:
                    score += 1
        scores[table] = score

    if scores:
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            return best
    return "GenericEvents"


def _kv_extras(fmt: str, analysis: dict) -> dict:
    return {"kv_delimiter": analysis["kv_delimiter"]} if fmt == "kv" and analysis.get("kv_delimiter") else {}


def _propose_heuristic_spec(source_name: str, analysis: dict) -> dict:
    """Build a declarative mapping spec from structure analysis."""
    fmt = analysis["format"]
    if fmt == "unknown":
        fmt = "json"  # default to JSON

    spec: dict[str, Any] = {
        "name": f"mapping_{source_name.replace('-', '_').replace('/', '_')[:40]}",
        "description": f"Auto-generated mapping for source {source_name}",
        "format": fmt,
        "target_table": "GenericEvents",
        "fields": {},
        "constants": {},
    }

    spec.update(_kv_extras(fmt, analysis))

    # Pick field keys from appropriate list
    field_data = analysis.get("json_keys", {}) if fmt == "json" else analysis.get("keys", {})

    # Guess target table
    keys = list(field_data.keys())
    target = _guess_target_table(keys)
    spec["target_table"] = target

    # Build field mappings from aliases
    mapped_columns = set()
    for key in keys:
        alias = FIELD_ALIASES.get(key.lower(), FIELD_ALIASES.get(key.lower().replace(".", "_")))
        if alias and alias not in mapped_columns:
            if fmt == "json":
                spec["fields"][alias] = f"$.{key}"
            else:
                spec["fields"][alias] = key
            mapped_columns.add(alias)

    # Unmapped keys go as hints in constants or description
    unmapped = [k for k in keys if k not in {f.lower() for f in FIELD_ALIASES}
                and k not in {f.lower().replace(".", "_") for f in FIELD_ALIASES}]
    if unmapped:
        spec["description"] += f". Unmapped fields: {', '.join(unmapped[:10])}."

    # Add time field if we find one
    time_keys = {"timestamp", "@timestamp", "time", "ts", "datetime", "date", "log_time"}
    for k in keys:
        if k.lower() in time_keys:
            path = f"$.{k}" if fmt == "json" else k
            spec["time"] = {"field": path, "format": "iso8601"}
            break

    # For csv: add column position hints
    if fmt == "csv":
        # Note: csv columns are col1, col2, etc. The aliases already map them.
        pass

    # For kv: already handled via key mappings
    # For regex: we don't auto-generate complex regexes; mark as manual
    if fmt == "regex":
        spec["description"] += " REGEX format requires manual pattern configuration."

    return spec


# ── helper: verify spec coverage ───────────────────────────────────────────────

def _verify_coverage(spec: dict, samples: list[str]) -> dict[str, Any]:
    """Test a MappingParser spec against samples and compute coverage.
    Returns {"coverage_pct": float, "total": int, "parsed": int, "errors": list[str]}
    """
    errors_spec = validate_spec(spec)
    if errors_spec:
        return {"coverage_pct": 0.0, "total": len(samples), "parsed": 0,
                "errors": errors_spec, "spec_errors": True}

    total = len(samples)
    parsed = 0
    errs: list[str] = []

    try:
        parser = MappingParser(spec)
    except ValueError as e:
        return {"coverage_pct": 0.0, "total": total, "parsed": 0,
                "errors": [str(e)], "spec_errors": True}

    for i, s in enumerate(samples):
        try:
            events = parser.parse(s, "test_source")
            if events and len(events) > 0:
                evt = events[0]
                # Check that at least one meaningful field was extracted
                meaningful = {k: v for k, v in evt.fields.items()
                              if v and k not in ("SourceId", "SourceType", "RawEvent", "TimeGenerated")}
                if meaningful:
                    parsed += 1
                else:
                    errs.append(f"sample[{i}]: no meaningful fields mapped")
            else:
                errs.append(f"sample[{i}]: parser returned no events")
        except Exception as exc:
            errs.append(f"sample[{i}]: {exc}")

    coverage = (parsed / total * 100) if total > 0 else 0.0
    return {"coverage_pct": round(coverage, 1), "total": total, "parsed": parsed,
            "errors": errs[:10]}  # limit error list
