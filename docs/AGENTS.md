# Agents design — siempl agentic SIEM

> **Scope:** triage, remediation, log-alert agents
> **Last updated:** 2026-10-12
> **Status:** implemented, tested (51 tests), no external API keys used

## Triage, remediation & log-alert agents

### Purpose

Automate L1 SOC triage: receive alerts, gather context deterministically, optionally enrich via LLM,
produce a verdict, and (per policy) close, escalate, comment, create temporary monitoring rules, or
trigger remediation stubs. All side effects are guarded by the policy matrix and dry-run mode.

### Architecture / data flow

```
Alert (new)  ──►  TriageAgent.execute(alert_id)
                      │
                      ├── 1. Gather context (deterministic, always)
                      │       alert + rule + evidence rows + entities +
                      │       related alerts (last 90 days)
                      │
                      ├── 2a. If AI enabled: LLM tool-using loop (max 6 steps)
                      │       Tools: run_kql, get_entity, get_related_alerts,
                      │       lookup_ip_reputation (stub, local entity store only)
                      │       Final output: structured verdict JSON
                      │
                      ├── 2b. If AI disabled: deterministic heuristic
                      │       Low-rep + low-sev + FP history → benign
                      │       High-rep or critical → needs_human
                      │       Else → needs_human
                      │
                      └── 3. Apply policy (resolve_policy: rule > severity > global)
                              off        → skip
                              monitor    → comment + may create temp rules
                              recommend  → comment only
                              auto_close → close if confidence ≥ threshold
                              auto_remediate → close + may trigger remediation stubs
```

### Public API (as actually implemented)

#### siempl.agents.triage

```python
class TriageAgent(Agent):
    """Investigate a single alert and produce a verdict."""
    name = "triage"

    def execute(self, alert_id: str, severity: str | None = None,
                rule_id: str | None = None, **kw) -> AgentResult
        # Returns AgentResult with output dict containing:
        #   alert_id, verdict, confidence, severity_adjustment, summary,
        #   evidence_refs, recommended_actions, monitor_entities,
        #   monitor_patterns, source, steps_used, tokens_in/out, cost_usd

def triage_new_alerts(db: Database, limit: int = 20) -> list[AgentResult]:
    """Scheduler entry point. Triages up to `limit` new alerts.
    Respects policy mode 'off'. Returns list of AgentResult."""

# Heuristic helpers (usable standalone, no LLM dependency):
def _heuristic_triage(db, alert, rule, entities) -> dict
def _run_kql_tool(db, query) -> dict        # safe, read-only wrapper
def _get_entity_tool(db, etype, value) -> dict
def _get_related_alerts_tool(db, entity_id) -> list
def _lookup_ip_reputation_tool(db, ip) -> dict  # stub, local store only
def _extract_json(text: str) -> dict | None      # robust vs code fences/garbage
```

#### siempl.agents.remediation

```python
class ConnectorRegistry:
    def register(name: str, fn) -> None
    def get(name: str) -> Callable | None
    def list_names() -> list[str]
    def invoke(db, name, target, *, alert_id, dry_run, **kw) -> dict

def get_registry() -> ConnectorRegistry  # pre-populated with stubs

# Stub connectors (all log to remediation_log with dry_run=True, never execute):
def block_ip(db, ip, *, alert_id, dry_run, **kw) -> dict
def disable_user(db, user, *, alert_id, dry_run, **kw) -> dict
def isolate_host(db, host, *, alert_id, dry_run, **kw) -> dict
def kill_process(db, pid, *, alert_id, dry_run, **kw) -> dict
```

#### siempl.agents.log_alert

```python
class LogAlertAgent(Agent):
    name = "log_alert"

    def execute(self, table: str, limit: int = 50,
                table_filter: str = "", **kw) -> AgentResult
        # Off by default (log_alert_agent_enabled=False).
        # Reads new rows since watermark, deduplicates by template,
        # batch-analyzes with cheap model, creates alerts.

# Template normalisation for dedup:
def _normalise_template(text: str) -> str
def _template_key(text: str) -> str
```

### Prompts (siempl/agents/prompts/)

| File | Purpose |
|---|---|
| `triage_system.md` | System prompt: evidence-first SOC triage with MITRE ATT&CK mental model |
| `triage_tools.md` | Tool descriptions: run_kql, get_entity, get_related_alerts, lookup_ip_reputation |
| `triage_verdict_schema.md` | Strict JSON schema for final verdict |

**Prompt provenance:** The system prompt synthesises established SOC L1 triage practice:

- **MITRE ATT&CK framework** is used as the mental model for mapping observed behaviour
  to tactics/techniques. This is standard across the industry; our prompt explicitly
  instructs the model to use ATT&CK as context.

- **Evidence-first triage** is borrowed from Microsoft's published guidance on Sentinel
  automation rules and the broader "don't close without citing evidence" discipline
  common in SOC playbooks (e.g., SOCless, The Hive, Cortex XSOAR triage playbooks).

- **Reputation-as-signal** (not automatic verdict) follows best practice documented in
  the SANS "Building a World-Class SOC" whitepaper and the MITRE ATT&CK Evaluations
  methodology: reputation enriches but does not replace human or agent reasoning.

- **Escalation thresholds** (confidence < 0.70, critical severity, novel patterns) are
  standard in tiered SOC models (Gartner SOC Maturity Model, NIST SP 800-61).

- **Cost discipline** (fewest tool calls, read evidence first) is an operational concern
  specific to LLM-powered SOCs, inspired by Dropzone AI's blog on agentic SOC cost
  efficiency and the general principle of "fetch only what you need."

- **Open-source AI SOC projects consulted for design patterns** (none used as drop-in):
  - [beenuar/AiSOC](https://github.com/beenuar/AiSOC) — open-source AI SOC with LLM-agent
    triage, MITRE ATT&CK investigation, and replayable decision ledger (MIT licensed).
  - [Ansh Soni's SOC Triage Agent guide](https://medium.com/@anshs5103/soc-triage-agent-a-developers-guide-to-agentic-alert-handling-for-new-age-security-operations-4e03552a77a5) —
    developer's guide covering agentic alert handling, MITRE-routed tools, and evidence
    normalization patterns.
  - [Angelo Pollari's AI-Powered SOC Triage](https://angelopollari187-hub.github.io/GithubAngeloP/ai-soc-triage.html) —
    ingestion → ATT&CK mapping → risk scoring → recommendation pipeline.

  **None of these provide a drop-in agent; our prompts and architecture are original work
  informed by public design patterns.**

### Policy matrix

`resolve_policy(db, "triage", severity=..., rule_id=...)` resolves the most specific
policy row (rule > severity > global). The default global policy is `recommend`.

| mode | can_close | can_escalate | can_create_temp_rules | behaviour |
|---|---|---|---|---|
| `off` | — | — | — | triage is skipped entirely |
| `monitor` | — | — | ✓ | observe only: creates temporary monitoring rules, does not close or escalate |
| `recommend` ✓ | ✓ | — | adds alert_comment only |
| `auto_close` ✓ | ✓ | ✓ | closes alerts when confidence ≥ `triage_close_confidence` (default 0.85); escalates otherwise |
| `auto_remediate` ✓ | ✓ | ✓ | same as auto_close, plus may trigger remediation stubs |

`can_remediate` defaults to `False` at every level. No remediation connector runs
without an explicit policy change + a non-stub connector.

### Extension points

1. **TI connectors:** Replace `lookup_ip_reputation`'s local-entity-store-only
   implementation with real AbuseIPDB/VirusTotal/Shodan calls. See the safety
   checklist in `siempl/agents/remediation.py` for each connector.

2. **Custom remediation connectors:** Register a function on `ConnectorRegistry`
   with the signature `(db, target, *, alert_id, dry_run, **kw) -> dict`. Every
   real connector must pass a safety review (operator approval, tested rollback,
   allowlist checking, scope validation) before going live.

3. **Custom triage heuristics:** Replace or extend `_heuristic_triage` with more
   sophisticated deterministic rules. The function receives alert, rule, and entity
   dicts and returns a verdict dict.

4. **Temporary rule TTL:** Default 24h. Override via settings
   `temp_rule_ttl_hours` (not implemented yet; hardcoded at 24h in `_maybe_create_temp_rules`).

5. **LogAlertAgent table-specific filters:** The `table_filter` parameter accepts
   arbitrary KQL where-clauses but is not validated. The `log_alert_allowlist`
   setting supports substring matching on `Message` only.

### Known limitations

1. **TriageAgent uses `agent:run_kql` queries for tool calls but does not collect
   `siempl.kql.QueryResult` return values.** The KQL module is consumed through
   `run_kql()` directly when available; when absent (KQL module not yet built), tool
   calls return `{"error": "KQL module not available"}`. This is handled gracefully
   — the LLM can adapt.

2. **Evidence parsing is lenient.** `alert.evidence` may be a JSON string, a list,
   or absent; all cases are handled without crashing, but malformed evidence silently
   produces empty lists.

3. **Entity store verdict application** (`apply_verdict`) is attempted on alert close
   but silently skipped if `siempl.entities` is not importable. This is a soft
   dependency on the detection module.

4. **Temporary rule creation** uses `siempl.detect.RuleStore.create` when available,
   else falls back to a direct `INSERT`. The direct INSERT does not validate the KQL
   beyond `compile_kql()`. The detection module's rule management (versioning, tuning
   history) is not replicated in the fallback path.

5. **LogAlertAgent is LLM-only.** When AI is disabled, the agent returns `skipped`
   — it has no heuristic alternative. This is by design: log-line alerting is
   inherently pattern-recognition work.

6. **log_alert watermark uses `settings` table,** which is key-value. For high-volume
   tables, this is one key per table. No partitioning or resumption checkpoint on
   failure.

7. **No concurrent alert triage locking.** Two scheduler cycles racing on the same
   alert could both call `triage_new_alerts`. The `agent_runs` table records both,
   but only the last `close_alert` wins. A `SELECT ... FOR UPDATE` or advisory lock
   pattern (not possible in DuckDB without external coordination) would be needed
   for production.

### How to test / run

```bash
# Run all agent tests (no network, no API keys):
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_agents_triage.py tests/test_agents_logalert.py -q

# Run triage manually (CLI, AI disabled, deterministic only):
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -c "
from siempl.db import Database
from siempl.agents.triage import TriageAgent
db = Database()
# ... seed alert + rule ...
agent = TriageAgent(db, dry_run=True)
res = agent.run(alert_id='a1')
print(res.summary, res.output)
"
```

### Implementation decisions (ADRs)

#### ADR-0001: Separate deterministic and LLM paths, not hybrid enrichment

**Context:** Should TriageAgent gather context deterministically, then have the LLM
"enrich" a pre-computed verdict, or should the LLM drive the entire investigation?

**Decision:** The LLM drives the investigation from fresh each time. The deterministic
context is bundled as the initial user message. If AI is disabled, a separate
heuristic function runs — not a "degraded LLM path."

**Consequences:**
- Simpler to reason about: two independent code paths, not one with fallback branches.
- LLM gets the same starting evidence as the heuristic, so both paths have equal
  information access.
- Risk: the heuristic never learns from new patterns the LLM discovers. The heuristic
  must be updated manually.

#### ADR-0002: Remediation stubs refuse execution even when dry_run=False

**Context:** Should the stub connectors respect the `dry_run` parameter?

**Decision:** No. Stubs always log with `dry_run=True` and `result='stub: would ...'`
regardless of the input `dry_run` value. This is a safety invariant: stubs MUST
NEVER touch the system.

**Consequences:**
- A real connector must be explicitly registered (overwriting the stub) before any
  action can execute.
- The `remediation_enabled` setting and `can_remediate` policy flag are independent
  safety layers that gate whether a real connector is even called.
- The `ConnectorRegistry` still receives the `dry_run` parameter so real connectors
  can honour it when they exist.

#### ADR-0003: LogAlertAgent watermark in settings table

**Context:** Where should the per-table watermark (last processed TimeGenerated) be stored?

**Decision:** In the `settings` table under key `log_alert_watermark_{table}`.

**Consequences:**
- Simple: no new table, no migration.
- One key per table; high-cardinality tables (~100s) would need a dedicated table.
- Settings table is already JSON-encoded, so datetime→string conversion is required.
- No checkpoint-on-failure: if the agent crashes mid-run, the watermark is not updated,
  and rows are re-scanned on next run. Acceptable since `limit` caps the blast radius.

### TODOs

- [ ] Add `temp_rule_ttl_hours` setting (currently hardcoded at 24h)
- [ ] Add DuckDB-level advisory lock or exclusive last-writer check for concurrent
  triage on the same alert
- [ ] LogAlertAgent: add per-day line cap enforcement (currently only caps per-run)
- [ ] LogAlertAgent: add KQL-based pre-filter (struct-field matching, not just Message substring)
- [ ] TriageAgent: track tool call latency and record in agent_runs.output
- [ ] Add a `--dry-run false` mode to the triage_new_alerts CLI path
- [ ] Integrate with the detection module's entity verdict application properly once EntityStore
  is fully implemented

## Onboarding, optimizer, discovery & tuning agents

> **Scope:** onboarding, optimizer, discovery, tuning agents
> **Last updated:** 2026-10-12
> **Status:** implemented, tested (83 tests), no external API keys used

### Purpose

Four agents handle the full lifecycle of SIEM data and rules:
- **OnboardingAgent:** auto-detect or propose parsers for new log sources
- **IngestionOptimizerAgent:** analyze table usage and recommend cost-saving filters/retention
- **RuleDiscoveryAgent:** validate source data quality, import Sigma/Sentinel rules, generate baseline rules
- **TuningAgent:** analyze rule performance (FP/TP rates) and recommend/propose tuning changes

All agents work deterministically (heuristics/SQL) without AI, and optionally enrich
via LLM when `ai_enabled=True`. With AI disabled (default), every agent runs
end-to-end and produces useful results.

### Public API

#### siempl.agents.onboarding

```python
class OnboardingAgent(Agent):
    name = "onboarding"

    def execute(self, source_id: str, samples: list[str|dict] | None = None, **kw) -> AgentResult
        # 1. Checks if source is already onboarded (parser + active status)
        # 2. Collects raw samples from GenericEvents (or provided samples)
        # 3. Runs siempl.ingest.parsers.auto_parse on each sample; tallies hits
        # 4. If a parser matches >30% of samples: recommends it
        # 5. If no parser fits: analyzes structure (JSON/KV/CSV/regex),
        #    proposes a MappingParser spec via heuristics
        # 6. Optionally enriches with LLM (if use_ai=True, retries once on validation errors)
        # 7. Verifies spec by running MappingParser over samples; reports coverage_pct
        # 8. On dry_run=False: persists parser to parsers table, updates sources,
        #    registers mapping parser at runtime

# Heuristic helpers usable standalone. Layout (split 2026-10-13, behavior unchanged):
#   siempl/agents/onboarding.py           OnboardingAgent + result builders; re-exports the helpers below
#   siempl/agents/_onboarding_analysis.py pure sample analysis (no agent/DB-write state)
#   siempl/agents/_onboarding_llm.py      LLM-assisted spec proposal/merge/fix (takes the agent as an arg)
# Heuristic helpers usable standalone:
def _collect_samples(db, source_id, samples=None) -> list[str]
def _detect_parser(samples, source_id) -> dict   # runs auto_parse, tallies parser hits
def _analyze_samples(samples) -> dict            # structure analysis (json/csv/kv/regex)
def _propose_heuristic_spec(source_name, analysis) -> dict  # builds MappingParser spec
def _verify_coverage(spec, samples) -> dict      # tests parser against samples
```

#### siempl.agents.optimizer

```python
class IngestionOptimizerAgent(Agent):
    name = "optimizer"

    def execute(self, window_days: int = 7, **kw) -> AgentResult
        # 1. Classify tables: used_by_rules / queried_by_humans / unused / empty
        # 2. For unused high-volume tables: analyze common message templates,
        #    propose ingest_filters (KQL where-expressions)
        # 3. For unused tables: recommend shorter retention
        # 4. Reports estimated savings (rows/bytes, pct)

# Public helpers for web UI / scheduler:
def apply_recommendation(db, rec_id, by) -> dict
    # Approve and apply ingest_filter or retention recommendations.
    # Inserts ingest_filters row (enabled=True) or table_retention entry.

def purge_expired(db) -> dict
    # Delete rows older than retention from data tables only.
    # Returns {tables: {table: deleted}, total_deleted, default_retention_days}.
    # Safety: only operates on DATA_TABLES, never metadata.

# Heuristic helpers:
def _classify_tables(db, window_days=7) -> list[dict]
    # Classification with row counts, rule references, human query references.
def _analyze_table_templates(db, table, limit=1000) -> list[dict]
    # Groups by EventCode + message prefix to find high-volume patterns.
def _propose_filter_from_template(event_code, message_prefix, table, count) -> dict|None
    # Builds KQL where-expression for common patterns.
```

#### siempl.agents.discovery

```python
class RuleDiscoveryAgent(Agent):
    name = "discovery"

    def execute(self, mode: str, http_client=None, **kw) -> AgentResult
        # mode="validate_sources": per source/table check data flow, event rates,
        #   last_event_at gaps, null rates of key columns, entity column fill rates,
        #   sourcetype classification. Reports warnings for gaps > 1h and nulls > 50%.
        #
        # mode="import_web": fetch Sigma/Sentinel rules matching tables with data,
        #   convert via sigma_to_rule/sentinel_to_rule, skip UnsupportedRule,
        #   validate by running each query once with row cap (flag noisy > 100 rows),
        #   deduplicate by source_ref, import DISABLED by default.
        #   http_client injection for tests; without client, gracefully skips.
        #
        # mode="generate": deterministic baseline-based rule ideas from SQL queries:
        #   - Rare process by host (ProcessEvents, count<5 in 7d)
        #   - Volume spike per source (AuthEvents, NetworkEvents, Syslog, 2σ above avg)
        #   - First-seen user logon from host (AuthEvents, first_seen in 30d)
        #   - Optional LLM-generated rules (compact schema/data digest, validated via compile_kql)
        #   All generated rules saved DISABLED, deduplicated by name, origin="ai_generated"
        #   with full description, triage_steps, entity_mappings for a triage agent.

# Heuristic helpers:
def _validate_source(db, source_id) -> dict
    # Returns table event counts, findiings, sourcetype, entity coverage.
def _generate_baseline_rules(db, agent) -> list[dict]
    # Returns saved rule records (all disabled, deduplicated).
```

#### siempl.agents.tuning

```python
class TuningAgent(Agent):
    name = "tuning"

    def execute(self, rule_ids: list[str]|None = None, window_days: int = 30, **kw) -> AgentResult
        # 1. For each enabled rule: compute alert counts, FP/TP verdict ratios,
        #    last_error, last_row_count
        # 2. Disable rules that errored 3+ times with no rows (rule_disable)
        # 3. For FP rate > 80% and volume > 10: recommend threshold/window adjustment (rule_tune)
        # 4. Detect repeated FP entities (≥3 occurrences) with low reputation (<40):
        #    recommend entity exclusion filter added to rule KQL query
        # 5. Detect duplicate alerts (same dedupe_key)
        # 6. Apply tunes via RuleStore.update (appends tuning_history) only when
        #    dry_run=False and policy mode allows (auto_close, auto_remediate for
        #    medium/high severity; high always applied)
        # 7. All tunes recoverable: old query versions kept in tuning_history JSON array
        # 8. Entity exclusion queries validated via compile_kql before application

# Heuristic helpers:
def _analyze_rules(db, window_days=30) -> list[dict]
    # Per-rule: alert_count, fp_count, tp_count, fp_rate, last_error, recommendation.
def _apply_tune(db, rule, tune, dry_run, agent, result) -> None
    # Applies rule_disable, rule_tune (threshold/window), or entity_exclusion.
def _add_tuning_history(db, rule_id, entry) -> None
    # Appends JSON entry to rules.tuning_history safely.
```

#### siempl.agents.registry

```python
AGENTS: dict[str, Type[Agent]]  # name -> class (lazy-populated, 6 agents)

def run_agent(db, name, **kw) -> AgentResult
    # Creates agent instance, calls agent.run(**kw).
    # Raises ValueError for unknown agent names.

def list_agents() -> list[str]
    # Sorted list of registered agent names.
```

#### siempl.agents.scheduler

```python
def start_agent_scheduler(db) -> threading.Thread | None
    # Daemon thread running on configurable intervals (gated by agent_schedule_enabled=False default).
    # Tasks: triage_new_alerts, tuning agent, optimizer agent, retention purge,
    # rule expiry. Respects per-agent intervals from settings. Never raises.
```

### Configuration (in siempl/config.py)

```python
DEFAULT_SETTINGS = {
    ...,
    "agent_schedule_enabled": False,          # master switch for recurring agent runs
    "agent_tuning_interval_minutes": 360,     # tuning every 6h
    "agent_optimizer_interval_minutes": 1440, # optimizer daily
    "agent_triage_interval_minutes": 5,       # triage every 5 min
    "agent_retention_interval_minutes": 1440, # retention purge daily
    "agent_rule_expiry_interval_minutes": 60, # rule expiry hourly
    "optimizer_high_volume_threshold": 10000, # rows/day above which to recommend filters
}
```

### Extension points

1. **New heuristics in OnboardingAgent:** Add field aliases to `FIELD_ALIASES` or
   table hints to `TABLE_HINTS`. The heuristic spec proposer uses these to map source
   fields to schema columns.

2. **New baseline rule generators:** Add detection queries to
   `_generate_baseline_rules()` following the existing pattern: check data exists,
   define name/description/triage_steps/query/entity_mappings, validate with
   compile_kql, deduplicate by name, insert disabled.

3. **Custom ingest filters:** Add pattern-extraction logic to
   `_analyze_table_templates()` or `_propose_filter_from_template()`. Filters are
   KQL where-expressions validated by compile_kql.

4. **LLM enrichment:** Every agent already has an LLM path inside try/except
   AIDisabledError. Add more sophisticated prompts or tool loops as needed.

5. **Scheduler tasks:** Add new recurring tasks to `start_agent_scheduler()` with
   corresponding interval settings.

### Known limitations

1. **KQL compile_kql has known bugs with string literals** (as of 2026-10-12).
   The KQL compiler is being repaired. The agents code against the documented
   contract (compile_kql/run_kql). Tests that exercise KQL through generated rules
   work because compile_kql succeeds for the simple numeric/column-only patterns used.
   Entity exclusion queries with string values may fail KQL validation; the agent
   applies the query change anyway with a comment.

2. **OnboardingAgent heuristic for regex-format sources** is minimal. The agent
   detects the format but cannot auto-generate regex patterns from samples.
   Manual spec editing is required for regex-based parsers.

3. **RuleDiscoveryAgent.generate mode KQL queries** use `summarize`, `stdev`,
   and `bin()` which may not be fully supported in the KQL compiler yet.
   Generated rules are validated via compile_kql before saving; those that
   fail validation are silently skipped.

4. **purge_expired uses COUNT-before-DELETE pattern** because DuckDB DELETE
   does not return rowcount reliably across versions. This is safe but adds
   an extra query per table.

5. **TuningAgent policy application** applies high-severity tunes immediately
   (even with dry_run=False) because disabling broken rules is considered safe.
   Threshold/lookback adjustments and entity exclusions require auto_close or
   auto_remediate policy mode.

### How to test

```bash
# Run all agents-2 tests (no network, no API keys):
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_agents2_*.py -q

# Run onboarding manually (CLI):
SIEMPL_HOME=$(mktemp -d) .venv/bin/python -c "
from siempl.db import Database
from siempl.agents.onboarding import OnboardingAgent
db = Database()
# ... seed source + samples ...
agent = OnboardingAgent(db, dry_run=True)
res = agent.run(input_ref='src1', source_id='src1')
print(res.summary, res.output)
"
```