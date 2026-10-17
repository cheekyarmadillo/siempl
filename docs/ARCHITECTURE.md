# siempl architecture

siempl is an agentic SIEM in Python: logs in, queryable tables, KQL-style querying, detection rules,
alerts/incidents/entities, and AI agents that onboard sources, optimize cost, discover/tune rules and triage.
Everything AI is **off by default** and gated (see "AI safety").

## Stack decisions (and why)

| Concern | Choice | Why / alternatives rejected |
|---|---|---|
| Storage/query engine | **DuckDB** (embedded columnar) | Fast analytic SQL, JSON, regex, time bucketing, zero ops, ~100MB RAM. ClickHouse is better at scale but heavy on this 7.7GB box and needs a server; Elastic/OpenSearch: JVM-heavy; SQLite: row store, slow aggregations. |
| User query language | **KQL subset -> DuckDB SQL** (own translator, `siempl/kql`) | Sentinel's public detection corpus (Azure/Azure-Sentinel on GitHub) is KQL; analysts know it. No OSS Python engine executes KQL, so we compile it. |
| Rule portability | **Sigma** (SigmaHQ) converted to KQL text on import | Sigma is the open, vendor-neutral standard with a huge public rule set. Imported rules are stored as KQL so one engine runs everything; original YAML kept in `rules.source_content`. |
| Log collection | syslog UDP/TCP (RFC3164/5424), HTTP JSON/NDJSON ingest endpoint, file tail | Standards-based; any shipper (rsyslog, Vector, Fluent Bit, Filebeat->HTTP) can feed it. |
| Data model | ASIM/ECS-lite, PascalCase (`siempl/schema.py`) | Entities (user/host/ip/process/file_hash/domain) are first-class columns on *every* table. |
| Web | **FastAPI + Jinja2 + HTMX**, hand-written CSS following Apple HIG (SF font stack, vibrancy/blur sidebar, light/dark) | No JS build chain; server-rendered, easy for a future agent to modify. |
| LLM | OpenRouter via `siempl/ai/llm.py` only | One chokepoint for the kill switch, key handling and budget caps. |
| Process model | **One process** (`python -m siempl`): FastAPI + collectors + rule scheduler + agent scheduler as threads/asyncio tasks | DuckDB permits a single writer process; sharing the connection avoids file-lock pain. |

## Layout

```
siempl/
  config.py        paths + DEFAULT_SETTINGS (single source of truth for settings)
  schema.py        data model + metadata DDL  (THE contract; read this first)
  db.py            Database: DuckDB wrapper, settings, insert_events
  ai/llm.py        LLMClient: only LLM entry point; kill switch + budget caps
  agents/base.py   Agent base class, policy resolution
  kql/             KQL parser + compiler to DuckDB SQL + run_kql()
  ingest/          pipeline, parsers (builtin + declarative), entity extraction, filters
  collectors/      syslog server, http ingest router, file tail, runner
  testdata/        downloaders for public datasets + synthetic attack data generator
  detect/          rule store, sigma/sentinel importers, scheduler, alert/incident creation
  entities/        entity store, reputation, graph edges
  agents/          onboarding, optimizer, discovery, tuning, triage, log_alert, remediation
  web/             FastAPI app, routes, templates, static CSS
  __main__.py      starts everything
docs/              ARCHITECTURE.md (this), KQL.md, PARSERS.md, RULES.md, AGENTS.md, UI.md, OPERATIONS.md, adr/
tests/
```

## Internal file layout notes

Some modules were split into private sibling files (leading underscore) to keep files small. The public
import path did not change; only import from the module named in the contracts below, never from the
private pieces.

| Public module | Private pieces | Notes |
|---|---|---|
| `siempl.kql._compiler` | `_compiler_sql`, `_compiler_columns`, `_compiler_funcs`, `_compiler_ops` | mixins on `KqlCompiler` |
| `siempl.agents.onboarding` | `_onboarding_analysis`, `_onboarding_llm` | helpers re-exported from onboarding |
| `siempl.agents.discovery` | `_discovery_utils` | validation + Sigma import helpers |
| `siempl.ingest.parsers` | `_parsers_core`, `_syslog`, `_auth`, `_cef`, `_apache`, `_json`, `_windows`, `_zeek`, `_winxml`, `_auto` | facade re-exporting everything; see PARSERS.md |

Code standards and the enforced quality ratchet: [STANDARDS.md](STANDARDS.md). History of the cleanup is in the git log.

## Module contracts (signatures other modules rely on — keep them stable)

### siempl.kql
```python
class KqlError(Exception): ...                       # parse/semantic error, message user-presentable
@dataclass class CompiledQuery: sql: str; params: list; tables: set[str]; columns: list[str] | None
@dataclass class QueryResult: columns: list[str]; rows: list[list]; truncated: bool; sql: str; elapsed_ms: float; tables: list[str]
def compile_kql(query: str, now: datetime | None = None) -> CompiledQuery
def run_kql(db: Database, query: str, *, limit: int = 10000, origin: str = "user", ref: str = "", log: bool = True) -> QueryResult
    # also writes query_log and bumps table_usage.(user_queries|rule_queries) per origin
def keywords() -> dict   # {"tables": [...], "operators": [...], "functions": [...]} for editor autocomplete
```
Time-window convention: rule queries are self-contained KQL and include their own TimeGenerated > ago(Nm) predicate; the scheduler calls run_kql(...) and never rewrites queries.

### siempl.ingest
```python
@dataclass class NormalizedEvent: table: str; fields: dict          # keys = schema column names
class IngestPipeline:
    def __init__(self, db: Database)
    def ingest(self, source_id: str, records: Iterable[str | dict], *, parser: str | None = None) -> IngestResult
        # resolves parser (arg > sources.parser > auto-detect), normalizes, applies enabled ingest_filters,
        # extracts+upserts entities, inserts via db.insert_events, bumps table_usage + sources.events_total,
        # creates a 'pending' source row on first sight of an unknown source_id.
@dataclass class IngestResult: received: int; inserted: int; dropped: int; failed: int; tables: dict[str, int]
siempl.ingest.parsers.get_parser(name) / list_parsers() / register(name)   # parse(raw, source_id) -> list[NormalizedEvent]
siempl.ingest.mapping.MappingParser(spec: dict)                              # declarative parsers, see docs/PARSERS.md
siempl.ingest.entities.extract_entities(table: str, fields: dict) -> list[tuple[str, str]]   # [(type, value)]
```

### siempl.entities
```python
class EntityStore:
    def __init__(self, db)
    def upsert(self, etype: str, value: str, seen: datetime | None = None, event_count: int = 1, **attrs) -> str   # returns entity_id
    def link(self, a_id: str, b_id: str, relation: str) -> None
    def get(self, entity_id) -> dict | None ; def search(self, q=None, etype=None, order="reputation DESC", limit=100) -> list[dict]
    def apply_verdict(self, alert_id: str, verdict: str, by: str) -> None   # moves reputation of alert entities, see docs
```
Reputation: 0 benign .. 100 malicious, 50 unknown. true_positive pushes up, false_positive/benign pushes down, with
diminishing steps and decay toward 50; private/RFC1918 ips and well-known benign (localhost, SYSTEM) are clamped to
never exceed 60.

### siempl.detect
```python
class RuleStore: create(rule: dict) -> str; get(id); list(enabled=None, origin=None); update(id, **fields) (appends tuning_history, bumps version); enable/disable(id); delete(id)
def sigma_to_rule(yaml_text: str, source_ref: str = "") -> dict          # raises UnsupportedRule
def sentinel_to_rule(yaml_text: str, source_ref: str = "") -> dict       # raises UnsupportedRule if KQL does not compile
class RuleRunner: __init__(db); run_rule(rule_id) -> list[alert_id]; run_due() -> dict ; ```
def start_scheduler(db) -> threading.Thread        # loops run_due() every 30s, expires temp rules
def create_alert(db, rule, rows, columns) -> str | None   # dedupe, entity mapping, incident grouping, entity alert_count
siempl.detect.importer.fetch_sigma(paths|query)/fetch_sentinel(...)     # network, caches under data/rules_cache
siempl.detect.builtin.install_builtin_rules(db)                         # hand-written KQL rules for our tables
```
**Rule description standard** (`rules.description` + `rules.triage_steps`): description states (1) the exact behaviour
matched, (2) why it matters / typical causes of false positives, (3) which fields in evidence matter. triage_steps is a
numbered list a triage agent can follow using `run_kql` and entity lookups. See docs/RULES.md.

### siempl.collectors
`SyslogServer(db, udp_port, tcp_port)`, `make_ingest_router(db) -> fastapi.APIRouter` (POST /api/ingest/{source_id}, JSON object, array or NDJSON),
`FileTailer(db, source_id, path)`, `start_collectors(db) -> list[Thread]` reading enabled sources of kind syslog/file.

### siempl.agents.* — all subclass `siempl.agents.base.Agent`
`OnboardingAgent.execute(source_id=..., samples=[...])` -> parser spec / target table recommendation (heuristic first, LLM optional).
`IngestionOptimizerAgent.execute()` -> recommendations (filters/retention) from table_usage + rule table refs + query_log.
`RuleDiscoveryAgent.execute(mode="validate_sources"|"import_web"|"generate")`.
`TuningAgent.execute()` -> rule tuning recommendations/changes from alert volume + verdicts.
`TriageAgent.execute(alert_id=...)` -> verdict close/escalate, honoring `resolve_policy`; remediation via `agents/remediation.py` (stub connectors, dry-run only).
`LogAlertAgent.execute(...)` -> optional per-line LLM alerting, batches lines, off by default.
`siempl.agents.registry.AGENTS` maps name -> class; `start_agent_scheduler(db)` runs recurring ones (tuning, optimizer) ONLY if ai/agents enabled in settings.

### siempl.web
`create_app(db) -> FastAPI`. Pages: Overview, Logs (KQL editor + results + table/schema browser), Incidents & Alerts,
Rules, Entities (list + detail), Ingestion (sources, tables, usage, recommendations), Agents (runs, recs), Settings (AI switch, caps, policy matrix).
JSON API under /api/*. Web must work with every agent module absent (feature-detect) so modules can land independently.

## AI safety (non-negotiable)
1. `settings.ai_enabled` defaults False; `LLMClient.chat` raises `AIDisabledError` before any network I/O.
2. Key only from env/`~/.config/siempl/openrouter.key`, read at call time. Never write it anywhere.
3. Daily $ and token caps enforced pre-call. Every call logged in `ai_usage`.
4. Agents default to dry-run; remediation connectors are stubs that only log.
5. Tests inject fake transports. **No test or dev command may call OpenRouter.** Do not add a key anywhere.
6. Agents must degrade gracefully without AI (heuristic path).

## Testing
`SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest -q`. Tests use `Database(str(tmp_path/'t.duckdb'))`.

## Documentation standards
Every module has a docstring (purpose, inputs, outputs, failure modes). Each area gets a `docs/<AREA>.md`
(design, data flow, extension points, known limits, how to test) in the style of an engineering design doc.
Significant decisions get a short ADR in `docs/adr/NNNN-title.md` (context, decision, consequences).
