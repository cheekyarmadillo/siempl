# siempl Detection Engine

## Purpose
The detection engine manages rules, imports Sigma/Sentinel rules from GitHub,
schedules rule execution, creates alerts and incidents, and feeds entity reputation
via alert verdict feedback.

## Architecture

```
                   ┌──────────────────────┐
                   │     Rule Importer     │
                   │  (sigma/sentinel)     │
                   └──────────┬───────────┘
                              │ rule dicts
                              ▼
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  builtin.py │────▶│    RuleStore     │────▶│     rules       │
│  22 rules   │     │   (CRUD+tuning)  │     │   (DuckDB)      │
└─────────────┘     └────────┬─────────┘     └────────┬────────┘
                             │                        │
                             ▼                        ▼
                    ┌──────────────────┐     ┌─────────────────┐
                    │   RuleRunner     │────▶│     alerts      │
                    │ (scheduler/run)  │     │   + incidents   │
                    └────────┬─────────┘     └────────┬────────┘
                             │                        │
                             ▼                        ▼
                    ┌──────────────────┐     ┌─────────────────┐
                    │  set_verdict()   │────▶│  EntityStore    │
                    │  (alert feedback)│     │  .apply_verdict │
                    └──────────────────┘     └─────────────────┘
```

## Data Flow
1. **Rule creation**: `RuleStore.create(rule)` inserts into `rules` table with `version=1`, empty `tuning_history`.
2. **Import**: `sigma_to_rule()` / `sentinel_to_rule()` convert upstream YAML → rule dict. `import_rules()` stores them DISABLED by default.
3. **Scheduling**: `start_scheduler(db)` runs a daemon thread; `run_due()` polls for rules whose `last_run_at + frequency_minutes <= now`.
4. **Execution**: `run_rule(rule_id)` runs the KQL/SQL query (via `run_rule_query` → raw DuckDB SQL), checks threshold, calls `create_alert()`.
5. **Alert creation**: extracts entities from result rows, builds a dedupe key (rule + entity set), groups alerts with shared entities into incidents (24h window), bumps entity alert_count and table_usage.
6. **Triage & feedback**: `set_verdict(alert_id, verdict, by)` closes the alert and calls `EntityStore.apply_verdict()` to move entity reputations.

## Public API

```python
from siempl.detect import (
    RuleStore, RuleRunner, UnsupportedRule,
    sigma_to_rule, sentinel_to_rule,
    create_alert, set_verdict, start_scheduler,
)
from siempl.detect.importer import fetch_sigma, fetch_sentinel, import_rules
from siempl.detect.builtin import install_builtin_rules

# Rule management
store = RuleStore(db)
store.create(rule_dict)              # → rule_id
store.get(rule_id)                   # → dict | None
store.list(enabled=True, origin="builtin")  # → list[dict]
store.update(rule_id, threshold=5)   # bumps version, appends tuning_history
store.enable/disable/delete(rule_id)

# Rule conversion (raises UnsupportedRule with reason)
rule = sigma_to_rule(yaml_text, source_ref="https://...")
rule = sentinel_to_rule(yaml_text, source_ref="https://...")

# Scheduling & execution
runner = RuleRunner(db)
runner.run_rule(rule_id)             # → list[alert_id]
runner.run_due()                     # → {"rules_checked": N, "alerts_generated": M}

# Alert feedback
set_verdict(db, alert_id, "true_positive", "tester")  # → bool

# Import
rules = fetch_sigma(max_files=20)        # fetches from GitHub, caches on disk
rules = fetch_sentinel(max_files=20)
import_rules(db, rules, enable=False)    # all rules DISABLED by default

# Built-in
install_builtin_rules(db)                # idempotent
```

## Sigma → KQL Conversion

### Field Mapping
Sigma field names are mapped to our schema columns:
| Sigma Field | Our Column |
|---|---|
| Image | ProcessPath |
| CommandLine | ProcessCmdLine |
| ParentImage | ParentProcessName |
| User | UserName |
| DestinationIp | DstIp |
| c-uri | Url |
| ... | ... |

Unmapped fields fall back to `Extra->>'field_name'`.

### Condition Translation
- `selection1 and selection2` → `(kql1) AND (kql2)`
- `selection1 or selection2` → `(kql1) OR (kql2)`
- `1 of them` → `OR` of all non-filter selections
- `all of them` → `AND` of all non-filter selections
- `not filter_*` → `NOT (kql)`
- Modifiers: `|contains`, `|startswith`, `|endswith` → `ILIKE`; `|re` → `regexp_matches`; `|cidr` → IP range check; `|count` → `GROUP BY ... HAVING`

### Aggregation
`Field|count: '>= N'` in a selection triggers aggregation mode: the row filter
from the selection is kept, then a canonical KQL
`| summarize cnt=count() by <group cols> | where cnt >= N` stage is appended
(group cols = the base fields of the non-count specs in the selection). This
matches the form used by the builtin rules and compiles via `compile_kql`.
(Changed 2026-10-12: previously emitted raw DuckDB SQL with GROUP BY/HAVING,
which neither compiled nor executed after the raw-SQL fallback was removed from
`_run_rule.py`.)

### Logsource → Table Resolution
| Sigma logsource | Our table |
|---|---|
| process_creation | ProcessEvents |
| network_connection | NetworkEvents |
| authentication | AuthEvents |
| file_event | FileEvents |
| web | WebAccess |
| ... | GenericEvents (fallback) |

## Sentinel Conversion
Azure-Sentinel detection YAML is converted by:
1. Mapping Sentinel table names to ours (SecurityEvent→AuthEvents, etc.)
2. Mapping column names via `SENTINEL_COLUMN_MAP`
3. Verifying the mapped query compiles with `compile_kql()` — incompatible rules raise `UnsupportedRule` with reason

## Built-in Rules
22 hand-written rules covering:
SSH brute force, password spray, encoded PowerShell, certutil download, new local admin,
scheduled task persistence, port scan, web scanner, DGA-like DNS, RDP/SMB lateral movement,
rare parent-child process, large outbound transfer, PowerShell download cradle,
service installation, registry persistence, WMI persistence, process injection,
DNS tunneling, process discovery, service account interactive logon.

Each rule follows the **Rule Description Standard**: description states exact behavior + why it matters + key evidence fields; triage_steps is a numbered list for a triage agent.

## Rule Query Execution
**Current state (2026-10-12)**: Rule queries are stored as raw DuckDB SQL and executed
directly via `siempl/detect/_run_rule.py`. The KQL compiler is still maturing; its
does not yet handle string literal values. Once the KQL compiler supports string literals,
rules will be ported to pure KQL syntax and the `_run_rule.py` fallback can be retired.

## Alert Deduplication
Alerts with the same `rule_id` and entity set within `frequency_minutes * 3` window
are deduplicated: `row_count` is bumped instead of creating a new alert.

## Incident Grouping
Alerts sharing any entity within 24h join the same incident. Incident severity is
the maximum of its alert severities.

## Known Limitations
- KQL compiler doesn't handle string literals yet (see above); rules use raw SQL.
- Sigma aggregation produces a KQL `summarize` stage from `Field|count`
  modifiers; complex aggregation conditions (e.g. `count() by X` mid-expression)
  are not parsed.
- Sentinel column mapping is best-effort; complex KQL operators may fail to compile.
- No rule performance impact analysis or query optimization yet.
- Temporary rules (origin=`ai_temporary`) expire but the expiration check is in the
  scheduler only — no cleanup of already-created alerts.

## Testing
```bash
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_detect.py -q
```
82 tests pass. Tests use temporary DuckDB databases; no network calls (importer
tests use mock HTTP clients).

## TODOs
- [ ] Port built-in rules to KQL syntax when KQL compiler supports string literals
- [ ] Add rule performance profiling (query cost estimation)
- [ ] Implement real network fetch verification for importer (manual step)
- [ ] Add incident deduplication across time windows
- [ ] Wire up agent policy resolution for triage auto-close
## Parser field contract (2026-10-12)

Builtin rules query normalized columns; parsers must populate them or rules
silently never fire. Verified contract for AuthEvents:

- sshd parser (`syslog_rfc3164`/`syslog_rfc5424` sub-parse): every auth event
  carries `AuthMethod="ssh"`, `TargetUserName`=<account being authenticated>
  (plus `UserName` kept), `EventAction="login"`, `EventResult`=
  success/failure. The wire sub-method (password/publickey/
  keyboard-interactive) lives in `LogonType`. Covered by
  `tests/test_sshd_real_logs.py` (real RFC3164+RFC5424 lines -> rules 1-3
  fire) and parser assertions in `tests/test_ingest.py`.
- windows_json 4624/4625: `TargetUserName`, `LogonType` (numeric string),
  `AuthMethod` from AuthenticationPackageName.

Root-cause fixed 2026-10-12: sshd used to emit `AuthMethod="password"` and no
`TargetUserName`, so rules 1-3 could only fire on synthetic windows_json rows.

## Sigma import improvements (2026-10-12)

- **Unmapped Sigma fields no longer reject the rule.** `_map_sigma_field`
  falls back to dynamic access on the JSON `Extra` column:
  `tostring(Extra.FieldName)` (bracket form for non-identifier names).
  Parsers stash unmapped source fields in `Extra`, so real SigmaHQ rules
  import and run instead of raising `UnsupportedRule`.
- **Numeric columns get unquoted literals** (`DstPort in (443, 8443)`, not
  `("443", ...)`); previously such rules silently matched nothing.
- **List-valued selections** (`selection:` as a YAML list of maps) are ORed,
  per Sigma semantics — was an AttributeError crash (15/60 real rules).
- **Embedded `N of pattern*` / `all of pattern*`** inside larger conditions
  (e.g. `selection and not 1 of filter_main_*`) now expand — 11/60 real rules.
- **`|cidr` modifier** now raises `UnsupportedRule` with a clear reason at
  conversion time instead of emitting a raw-SQL fragment that fails KQL parse.
- **KQL compiler**: nested `and`/`or` groups are now parenthesized on emit —
  `(A or B) and not C` used to flatten to `A or B and not C`, which SQL binds
  as `A or (B and not C)` and broke `not filter` semantics.
- **Real-network sample (60 SigmaHQ rules, unauthenticated GitHub raw/API)**:
  31/60 imported before these fixes, 58/60 after. The 2 remaining failures
  are `|cidr` filter rules (unsupported, clean reason). Run 2026-10-12.
- End-to-end coverage: `tests/test_sigma_import.py` (6 realistic Sigma rules
  — contains|all, endswith, lists, `1 of selection*`, `not filter`, Extra
  fallback — import AND execute against fixture data with alert/no-alert).
