# Parser System — Design Document

## Purpose
Convert raw log records (strings, JSON dicts) into `NormalizedEvent` objects
with the correct target table and typed columns. Supports both built-in parsers
and a declarative mapping engine for AI-onboarded sources.

## Source layout (split 2026-10-13)

`siempl/ingest/parsers.py` used to hold every built-in parser (2400 lines). It is now a thin facade: it re-exports every
name it used to define, so `from siempl.ingest.parsers import parse_cef` (and `parsers.parse_cef`, `get_parser`,
`list_parsers`, `auto_parse`) are unchanged. The code lives in one module per format. All definitions were moved
verbatim (verified by comparing the syntax tree of each of the 73 definitions); only a few shared helpers
moved to the core module.

| Module | Contents |
|---|---|
| `_parsers_core.py` | registry (`register`, `get_parser`, `list_parsers`), `_utcnow`, `_make_extra`, and helpers shared by several formats (`_as_dict`, `_json_get`, `_parse_json_timestamp`) |
| `_parsers_syslog.py` | `syslog_rfc3164`, `syslog_rfc5424` |
| `_parsers_auth.py` | sshd and sudo sub-parsers (called by the syslog parsers; not registered themselves) |
| `_parsers_cef.py` | `cef` |
| `_parsers_apache.py` | `apache_combined` |
| `_parsers_json.py` | `generic_json` + the `JSON_ALIASES` table |
| `_parsers_windows.py` | `windows_json` + field helpers |
| `_parsers_zeek.py` | `zeek_conn`, `zeek_dns` |
| `_parsers_winxml.py` | `windows_xml` |
| `_parsers_auto.py` | `auto_parse` and the `_looks_like_*` format sniffers |

Things that bite when editing here:
- **Registration order is behavior.** `list_parsers()` order feeds the sources "detect parser" endpoint. `parsers.py` imports the
  modules in the original definition order inside an `# isort: off` / `# isort: on` region (ruff's import sorter had
  alphabetised them and silently changed the order). `ocsf` is imported last (it imports `_utcnow`/`register` back from
  `parsers`) behind an `# isort: split` marker. `tests/test_parsers_registry_order.py` pins the order, so a sorter or
  a careless edit fails a test instead of passing review.
- **Patch names where they are looked up.** `_utcnow` is bound in each `_parsers_*` module, so a test that freezes the clock
  must patch it in the module that calls it (see the fixture in `tests/test_char_ingest_cef.py`).
- New shared helpers go in `_parsers_core.py` (keeps the import graph acyclic: core <- formats <- auto <- parsers).

## Built-in Parsers

| Parser | Input Format | Target Tables |
|--------|-------------|---------------|
| `syslog_rfc3164` | BSD syslog (RFC 3164) | Syslog, AuthEvents (sshd/sudo sub-parse) |
| `syslog_rfc5424` | IETF syslog (RFC 5424) | Syslog, AuthEvents |
| `cef` | ArcSight Common Event Format | GenericEvents |
| `apache_combined` | Apache/Nginx combined log | WebAccess |
| `generic_json` | Arbitrary JSON with heuristic aliasing | GenericEvents |
| `windows_json` | Winlogbeat / OTRF Security Datasets | AuthEvents, ProcessEvents, NetworkEvents, FileEvents, GenericEvents |
| `zeek_conn` | Zeek connection log JSON | NetworkEvents |
| `zeek_dns` | Zeek DNS log JSON | NetworkEvents |

All parsers preserve `RawEvent` (the original record) and never drop data.

### SSH Sub-Parser
When `syslog_rfc3164` or `syslog_rfc5424` detects `app_name == "sshd"`, it
produces an `AuthEvents` record instead of `Syslog`, extracting:
- `UserName` and `TargetUserName` / `SrcIp` from "Failed|Accepted|Invalid user" patterns
  (both invalid-user variants and `keyboard-interactive/pam` are handled)
- `EventResult` = success/failure
- `AuthMethod` = `ssh` for every sshd auth event (the builtin-rule contract;
  see docs/RULES.md)
- `LogonType` = the wire sub-method: password/publickey/keyboard-interactive/none
- `FailureReason` for parseable failures

### Sudo Sub-Parser
When `app_name == "sudo"`, produces `AuthEvents` with `TargetUserName` and
`EventAction = "session_elevation"`.

### Windows JSON Mapping
Maps `EventID` to target tables:
- 4624/4625 → AuthEvents
- 4688 → ProcessEvents
- Sysmon 1 → ProcessEvents
- Sysmon 3 → NetworkEvents
- Sysmon 22 → NetworkEvents (DNS)
- Sysmon 11 → FileEvents
- Others → GenericEvents

Resolves fields from both `event_data` sub-dict and flat top-level keys
(Winlogbeat and OTRF styles).

## Auto-Detection

`auto_parse(raw, source_id)` checks in order:
1. `CEF:` prefix → CEF parser
2. `<NNN>` PRI → Syslog (5424 if `1 ` follows; 3164 otherwise)
3. IP address prefix → Apache/combined
4. JSON dict with `EventID` / `event_data` → Windows JSON
5. JSON dict with `uid` + `id.orig_h` → Zeek conn/DNS
6. JSON dict → generic_json
7. Everything else → GenericEvents (raw string preserved)

## Mapping Parser (Declarative Engine)

`siempl.ingest.mapping.MappingParser` is the tool AI onboarding agents emit.
Specs are JSON objects validated by `validate_spec(spec) → list[errors]`.

### Spec Format

```json
{
  "name": "my_parser",
  "description": "...",
  "format": "json|regex|kv|csv",
  "target_table": "AuthEvents",
  "time": {"field": "@timestamp", "format": "iso8601|unix|unix_ms|<strptime>"}, 
  "fields": {
    "UserName": "$.user.name",
    "SrcIp": {"path": "$.source.ip", "transform": "lower|upper|strip|int|float|bool"}
  },
  "constants": {"EventResult": "success"},
  "when": {"field": {"path": "$.status"}, "op": "eq|neq|in|contains|regex|exists", "value": "error"},
  "json_path_prefix": "$.event_data",
  "regex_pattern": "(?P<user>\\w+) from (?P<ip>[\\d.]+)",
  "kv_delimiter": "|"
}
```

### Field Paths
Simple dotted paths (`$.user.name` → `obj["user"]["name"]`). No bracket syntax,
no wildcards. Path safety: only dict key access, no evaluation.

### Transforms
`lower | upper | strip | int | float | bool` — pure data manipulation, no eval.

### When Conditions
Filter records before field mapping. Operators: `eq`, `neq`, `in`, `contains`,
`regex` (with 5s timeout), `exists`. If no `when` block, all records match.

### Formats
- **json**: record is parsed as JSON dict
- **csv**: record split by `csv.reader`; columns named `col1`, `col2`, ...
- **kv**: `key=value` pairs separated by whitespace, or by `kv_delimiter` (1-3 characters, e.g. `|`) for records like
  `TLX|v2|dev=GW-7F21|evt=ZONE_ARM|ts=2026-10-14T23:13:50Z` (parts without `=` are ignored; map fields by bare key name)
- **regex**: pattern from `regex_pattern` key; uses named groups (a regex spec without a pattern validates but parses nothing)

### Safety
- No `eval()`, no code execution
- Regex with 5-second timeout
- Size limit: 100 KB per record
- Strict spec validation rejects unknown keys

### Validation
`validate_spec(spec) → list[error_strings]` checks:
- Required keys (`name`, `target_table`) present
- `target_table` is a valid DATA_TABLES entry
- `format` is one of the known values
- Field specs have valid `transform` values
- `constants` values are JSON scalars
- Unknown top-level keys rejected (prevents typos)
- `regex_pattern` must compile; `kv_delimiter` must be a 1-3 character string

The onboarding agent only auto-applies a proposed mapping parser when it parses at least 50% of the samples
(`MIN_AUTO_APPLY_COVERAGE` in `siempl/agents/onboarding.py`); below that it records the recommendation and marks the
run `needs_human`.

## Extension Points

1. **New built-in parser:** `register("name")(fn)` where `fn(raw, source_id) → list[NormalizedEvent]`
2. **New transform:** add to `VALID_TRANSFORMS` and `_apply_transform()`
3. **New format:** add to `VALID_FORMATS` and implement in `MappingParser.parse()`

## How to Test

```
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_ingest.py -q -k "parse"
```
## OCSF (`ocsf`)

Added 2026-10-13. Source: `siempl/ingest/ocsf.py`. Spec: https://schema.ocsf.io (written against 1.x; tested on 1.3-shaped events).
OCSF was picked over CEF because it is a typed, class-based event schema (CEF is flat key=value and already has its own parser).

- **Detection:** a JSON object with `class_uid` plus `category_uid`/`activity_id`/`metadata`, or a JSON array of such objects. Auto-detected by `auto_parse`, or set the source parser to `ocsf`.
- **Routing by `class_uid`:** 1001 File System -> FileEvents; 1007 Process -> ProcessEvents; 3001-3004 (account change, authentication, authorize session, entity mgmt) -> AuthEvents;
  4001/4003/4005-4007 (network, DNS, ...) -> NetworkEvents; 4002 HTTP -> WebAccess; unknown class -> by `category_uid` (1 file, 3 auth, 4 network), else GenericEvents.
- **Mapped:** `time` (epoch ms, also seconds or ISO-8601), `activity_id` -> EventAction (class-specific names), `status_id` -> EventResult, `device`/`src_endpoint` host, `actor.user`/`user`/`src_user` -> UserName,
  endpoints -> Src/Dst Ip+Port, `process` (name, cmd_line, pid, file path, sha256>sha1>md5, parent_process, integrity), `file`, `http_request`/`http_response`, `connection_info` (protocol, direction), `traffic` bytes,
  `query.hostname` -> DnsQuery/Domain, `dst_user`/`logon_type`/`auth_protocol`/`status_detail` -> TargetUserName/LogonType/AuthMethod/FailureReason.
- **Nothing is dropped:** every other attribute (metadata, enrichments, unmapped, finding_info, observables, class_name, type_uid, ...) and `severity` (as a name) land in `Extra`, queryable with `Extra->>'...'` in SQL rules.
- **Not covered:** OCSF classes without a natural table (findings, API activity, inventory, email, ...) go to GenericEvents with the class in EventCode; observables/enrichment objects are kept but not flattened.
- Tests: `tests/test_parser_ocsf.py`.
