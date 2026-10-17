"""Common data model. THE contract between collectors/parsers, KQL engine, rules, entities, UI.

Design: ASIM/ECS-lite. Every event table shares COMMON_COLUMNS (incl. the entity columns),
then adds table-specific columns. Column names are PascalCase (KQL is case-sensitive; this
matches Microsoft Sentinel conventions). Table names are PascalCase too.
Add a table => add it to DATA_TABLES; it is auto-created by Database.init_schema().
"""
from __future__ import annotations

# (name, duckdb_type, description)
COMMON_COLUMNS = [
    ("TimeGenerated", "TIMESTAMP", "Event time (UTC, naive). Falls back to ingest time."),
    ("IngestTime", "TIMESTAMP", "When siempl received the event (UTC, naive)."),
    ("SourceId", "VARCHAR", "sources.source_id that produced the event."),
    ("SourceType", "VARCHAR", "Parser/format name (syslog5424, apache_combined, windows_json, ...)."),
    ("EventCode", "VARCHAR", "Vendor event id (e.g. Windows 4625, Sysmon 1). String on purpose."),
    ("EventAction", "VARCHAR", "Normalized verb: login, logoff, process_start, connect, request, ..."),
    ("EventResult", "VARCHAR", "success | failure | unknown"),
    ("HostName", "VARCHAR", "ENTITY host: where the event happened."),
    ("UserName", "VARCHAR", "ENTITY user: acting account."),
    ("SrcIp", "VARCHAR", "ENTITY ip: source address (VARCHAR, not INET, for simplicity)."),
    ("DstIp", "VARCHAR", "ENTITY ip: destination address."),
    ("SrcPort", "INTEGER", ""),
    ("DstPort", "INTEGER", ""),
    ("ProcessName", "VARCHAR", "ENTITY process: image basename (e.g. powershell.exe)."),
    ("ProcessCmdLine", "VARCHAR", ""),
    ("Message", "VARCHAR", "Human readable summary / original message text."),
    ("RawEvent", "VARCHAR", "Original record, verbatim. Never dropped by parsers."),
    ("Extra", "JSON", "Source fields that had no column. Query with Extra->>'key'."),
]

DATA_TABLES: dict[str, dict] = {
    "Syslog": {
        "description": "RFC3164/5424 syslog and similar Unix daemon logs.",
        "columns": [("Facility", "VARCHAR", ""), ("SeverityLevel", "INTEGER", "0=emerg..7=debug"),
                    ("AppName", "VARCHAR", ""), ("ProcessId", "INTEGER", "")],
    },
    "AuthEvents": {
        "description": "Authentication events (ssh, windows logon 4624/4625, sudo, web auth).",
        "columns": [("AuthMethod", "VARCHAR", ""), ("LogonType", "VARCHAR", ""),
                    ("TargetUserName", "VARCHAR", "ENTITY user: account being authenticated"),
                    ("FailureReason", "VARCHAR", "")],
    },
    "ProcessEvents": {
        "description": "Process creation (Sysmon 1, Windows 4688, auditd execve).",
        "columns": [("ProcessId", "INTEGER", ""), ("ProcessPath", "VARCHAR", ""),
                    ("ParentProcessName", "VARCHAR", "ENTITY process"), ("ParentProcessId", "INTEGER", ""),
                    ("ParentCmdLine", "VARCHAR", ""), ("FileHash", "VARCHAR", "ENTITY file_hash (sha256 preferred)"),
                    ("IntegrityLevel", "VARCHAR", "")],
    },
    "NetworkEvents": {
        "description": "Network connections, DNS, firewall, proxy (Sysmon 3/22, zeek, firewall logs).",
        "columns": [("ProcessPath", "VARCHAR", "Full image path of the process (Sigma Image)"),
                    ("ProcessId", "INTEGER", ""),
                    ("Protocol", "VARCHAR", ""), ("BytesIn", "BIGINT", ""), ("BytesOut", "BIGINT", ""),
                    ("Direction", "VARCHAR", "inbound|outbound|internal"),
                    ("DnsQuery", "VARCHAR", "ENTITY domain"), ("Url", "VARCHAR", ""),
                    ("Domain", "VARCHAR", "ENTITY domain")],
    },
    "WebAccess": {
        "description": "HTTP access logs (apache/nginx combined, IIS, WAF).",
        "columns": [("HttpMethod", "VARCHAR", ""), ("Url", "VARCHAR", ""), ("UrlPath", "VARCHAR", ""),
                    ("StatusCode", "INTEGER", ""), ("UserAgent", "VARCHAR", ""),
                    ("Referrer", "VARCHAR", ""), ("Bytes", "BIGINT", "")],
    },
    "FileEvents": {
        "description": "File create/modify/delete (Sysmon 11, auditd, FIM).",
        "columns": [("ProcessPath", "VARCHAR", "Full image path of the process (Sigma Image)"),
                    ("ProcessId", "INTEGER", ""),
                    ("FilePath", "VARCHAR", ""), ("FileName", "VARCHAR", ""),
                    ("FileHash", "VARCHAR", "ENTITY file_hash"), ("Operation", "VARCHAR", "")],
    },
    "SiemplAudit": {
        "description": "Audit trail of every action taken inside siempl by users and agents (self-log source).",
        "columns": [("Actor", "VARCHAR", "user:<name> | agent:<name> | system"),
                    ("ActorType", "VARCHAR", "user|agent|system"),
                    ("Action", "VARCHAR", "dotted verb, e.g. rule.create, alert.verdict, agent.run, source.update"),
                    ("TargetType", "VARCHAR", "rule|alert|incident|entity|source|agent|setting|..."),
                    ("TargetId", "VARCHAR", ""),
                    ("Outcome", "VARCHAR", "ok|error|denied|dry_run")],
    },
    "GenericEvents": {
        "description": "Fallback for sources with no better table. Onboarding agent should migrate these.",
        "columns": [],
    },
}

# column -> entity type. Used by ingest (entity upsert) and rules (default entity mapping).
ENTITY_COLUMNS: dict[str, str] = {
    "UserName": "user", "TargetUserName": "user",
    "HostName": "host",
    "SrcIp": "ip", "DstIp": "ip",
    "ProcessName": "process", "ParentProcessName": "process",
    "FileHash": "file_hash",
    "Domain": "domain", "DnsQuery": "domain",
}
ENTITY_TYPES = ["user", "host", "ip", "process", "file_hash", "domain"]


def table_columns(table: str) -> list[tuple[str, str, str]]:
    return COMMON_COLUMNS + DATA_TABLES[table]["columns"]


def data_table_ddl(table: str) -> str:
    cols = ",\n  ".join(f'"{n}" {t}' for n, t, _ in table_columns(table))
    return f'CREATE TABLE IF NOT EXISTS "{table}" (\n  {cols}\n);'


# ---------------------------------------------------------------- metadata tables
META_DDL = """
CREATE TABLE IF NOT EXISTS settings (key VARCHAR PRIMARY KEY, value JSON, updated_at TIMESTAMP DEFAULT now());

-- Log sources. status: pending (seen, no parser) | active | paused
CREATE TABLE IF NOT EXISTS sources (
  source_id VARCHAR PRIMARY KEY, name VARCHAR, kind VARCHAR,          -- kind: syslog|http|file|testdata
  parser VARCHAR, target_table VARCHAR, status VARCHAR DEFAULT 'pending',
  config JSON, created_at TIMESTAMP DEFAULT now(), last_event_at TIMESTAMP,
  events_total BIGINT DEFAULT 0, notes VARCHAR);

-- Declarative mapping parsers (generated by the onboarding agent or hand-written). See docs/PARSERS.md
CREATE TABLE IF NOT EXISTS parsers (
  name VARCHAR PRIMARY KEY, spec JSON, target_table VARCHAR, origin VARCHAR,  -- builtin|ai|manual
  sample VARCHAR, created_at TIMESTAMP DEFAULT now());

-- Ingest-time drop filters (recommended by the optimizer, applied by the pipeline).
CREATE TABLE IF NOT EXISTS ingest_filters (
  filter_id VARCHAR PRIMARY KEY, table_name VARCHAR, expression VARCHAR,     -- KQL where-expression; matching rows are DROPPED
  description VARCHAR, enabled BOOLEAN DEFAULT FALSE, origin VARCHAR, created_at TIMESTAMP DEFAULT now(),
  dropped_total BIGINT DEFAULT 0);

CREATE TABLE IF NOT EXISTS table_retention (table_name VARCHAR PRIMARY KEY, retention_days INTEGER);

-- Daily per-table stats, written by ingest + KQL layer; read by the optimizer agent.
CREATE TABLE IF NOT EXISTS table_usage (
  day DATE, table_name VARCHAR, rows_ingested BIGINT DEFAULT 0, bytes_ingested BIGINT DEFAULT 0,
  rule_queries BIGINT DEFAULT 0, user_queries BIGINT DEFAULT 0, alerts_generated BIGINT DEFAULT 0,
  PRIMARY KEY (day, table_name));

CREATE TABLE IF NOT EXISTS query_log (
  ts TIMESTAMP DEFAULT now(), origin VARCHAR, ref VARCHAR, tables VARCHAR[], kql VARCHAR,
  rows_returned BIGINT, elapsed_ms DOUBLE, error VARCHAR);       -- origin: user|rule|agent

CREATE TABLE IF NOT EXISTS rules (
  rule_id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL,
  description VARCHAR,          -- WHAT it fires on + WHY it matters. Written for a triage agent.
  triage_steps VARCHAR,         -- numbered first investigation steps (markdown).
  severity VARCHAR,             -- informational|low|medium|high|critical
  query VARCHAR NOT NULL,       -- KQL (canonical; Sigma/Sentinel imports are converted to KQL)
  tables VARCHAR[], frequency_minutes INTEGER DEFAULT 5, lookback_minutes INTEGER DEFAULT 5,
  threshold INTEGER DEFAULT 1,  -- fire when result rows >= threshold
  mitre_tactics VARCHAR[], mitre_techniques VARCHAR[],
  entity_mappings JSON,         -- [{"entity_type":"user","column":"UserName"}, ...]
  enabled BOOLEAN DEFAULT TRUE,
  origin VARCHAR,               -- builtin|sigma|sentinel|ai_generated|ai_temporary|manual
  source_ref VARCHAR,           -- upstream URL/path for imports
  source_content VARCHAR,       -- original upstream rule text (yaml)
  expires_at TIMESTAMP,         -- temporary rules (monitoring) auto-disable at this time
  version INTEGER DEFAULT 1, tuning_history JSON DEFAULT '[]',
  query_lang VARCHAR DEFAULT 'kql',   -- kql | sql (sql = DuckDB SELECT from pySigma; time window applied by the runner)
  last_run_at TIMESTAMP, last_error VARCHAR, last_row_count BIGINT,
  created_at TIMESTAMP DEFAULT now(), updated_at TIMESTAMP DEFAULT now());

-- Alerts. status: new | triaging | closed | escalated.  verdict: true_positive|false_positive|benign|unknown
CREATE TABLE IF NOT EXISTS alerts (
  alert_id VARCHAR PRIMARY KEY, rule_id VARCHAR, title VARCHAR, severity VARCHAR,
  status VARCHAR DEFAULT 'new', verdict VARCHAR, verdict_by VARCHAR,       -- verdict_by: human:<name>|agent:<name>
  description VARCHAR, created_at TIMESTAMP DEFAULT now(), updated_at TIMESTAMP DEFAULT now(),
  window_start TIMESTAMP, window_end TIMESTAMP, row_count BIGINT, evidence JSON,   -- evidence: first N result rows
  entities JSON,                -- [{"type":"ip","value":"1.2.3.4"}]
  incident_id VARCHAR, dedupe_key VARCHAR, mitre_techniques VARCHAR[],
  alert_number BIGINT, owner VARCHAR, reputation_applied BOOLEAN DEFAULT FALSE);   -- status: new|active|closed_tp|closed_fp

CREATE TABLE IF NOT EXISTS incidents (
  incident_id VARCHAR PRIMARY KEY, title VARCHAR, severity VARCHAR, status VARCHAR DEFAULT 'new',
  owner VARCHAR, created_at TIMESTAMP DEFAULT now(), updated_at TIMESTAMP DEFAULT now(), summary VARCHAR);

CREATE TABLE IF NOT EXISTS alert_comments (
  comment_id VARCHAR PRIMARY KEY, alert_id VARCHAR, author VARCHAR, body VARCHAR, ts TIMESTAMP DEFAULT now());

-- Entities. reputation: 0 (benign) .. 100 (malicious), 50 = unknown. Moved by alert verdicts.
CREATE TABLE IF NOT EXISTS entities (
  entity_id VARCHAR PRIMARY KEY,                    -- "<type>:<value lowercased>"
  type VARCHAR, value VARCHAR, first_seen TIMESTAMP, last_seen TIMESTAMP,
  reputation DOUBLE DEFAULT 50, tp_count INTEGER DEFAULT 0, fp_count INTEGER DEFAULT 0,
  alert_count INTEGER DEFAULT 0, event_count BIGINT DEFAULT 0, attributes JSON DEFAULT '{}',
  watch BOOLEAN DEFAULT FALSE, notes VARCHAR);
CREATE TABLE IF NOT EXISTS entity_edges (
  src_entity VARCHAR, dst_entity VARCHAR, relation VARCHAR, first_seen TIMESTAMP, last_seen TIMESTAMP,
  weight BIGINT DEFAULT 1, PRIMARY KEY (src_entity, dst_entity, relation));

-- Denormalized side table: which (entity, data_table) pairs have been seen.
-- Populated at ingest time; backfilled lazily on first entities-list load.
CREATE TABLE IF NOT EXISTS entity_tables (
  entity_id VARCHAR, table_name VARCHAR,
  first_seen TIMESTAMP, last_seen TIMESTAMP, event_count BIGINT DEFAULT 0,
  PRIMARY KEY (entity_id, table_name));

-- Agent activity policy. mode: off | monitor | recommend | auto_close | auto_remediate
-- scope: global | severity | rule (specific rule_id) ; most specific wins: rule > severity > global
CREATE TABLE IF NOT EXISTS agent_policy (
  agent VARCHAR, scope VARCHAR, scope_value VARCHAR, mode VARCHAR,
  can_close BOOLEAN DEFAULT TRUE, can_escalate BOOLEAN DEFAULT TRUE,
  can_remediate BOOLEAN DEFAULT FALSE, can_create_temp_rules BOOLEAN DEFAULT TRUE,
  PRIMARY KEY (agent, scope, scope_value));

CREATE TABLE IF NOT EXISTS agent_runs (
  run_id VARCHAR PRIMARY KEY, agent VARCHAR, started_at TIMESTAMP DEFAULT now(), finished_at TIMESTAMP,
  status VARCHAR, dry_run BOOLEAN, input_ref VARCHAR, summary VARCHAR, output JSON, error VARCHAR,
  tokens_in BIGINT DEFAULT 0, tokens_out BIGINT DEFAULT 0, cost_usd DOUBLE DEFAULT 0);

-- Recommendations from agents (optimizer, tuning, discovery) for human approval.
CREATE TABLE IF NOT EXISTS recommendations (
  rec_id VARCHAR PRIMARY KEY, agent VARCHAR, kind VARCHAR,   -- ingest_filter|retention|rule_tune|rule_disable|rule_import|new_rule|onboard_source
  target VARCHAR, title VARCHAR, rationale VARCHAR, payload JSON, est_savings VARCHAR,
  status VARCHAR DEFAULT 'open', created_at TIMESTAMP DEFAULT now(), decided_at TIMESTAMP, decided_by VARCHAR);

CREATE TABLE IF NOT EXISTS remediation_log (
  action_id VARCHAR PRIMARY KEY, alert_id VARCHAR, agent VARCHAR, action VARCHAR, target VARCHAR,
  dry_run BOOLEAN, result VARCHAR, ts TIMESTAMP DEFAULT now());

CREATE TABLE IF NOT EXISTS ai_usage (
  ts TIMESTAMP DEFAULT now(), agent VARCHAR, model VARCHAR, tokens_in BIGINT, tokens_out BIGINT, cost_usd DOUBLE);
"""



# Idempotent migrations for databases created before a column existed. Run by Database.init_schema().
MIGRATIONS: list[str] = [
    "ALTER TABLE rules ADD COLUMN IF NOT EXISTS query_lang VARCHAR DEFAULT 'kql'",
    'ALTER TABLE "NetworkEvents" ADD COLUMN IF NOT EXISTS "ProcessPath" VARCHAR',
    'ALTER TABLE "NetworkEvents" ADD COLUMN IF NOT EXISTS "ProcessId" INTEGER',
    'ALTER TABLE "FileEvents" ADD COLUMN IF NOT EXISTS "ProcessPath" VARCHAR',
    'ALTER TABLE "FileEvents" ADD COLUMN IF NOT EXISTS "ProcessId" INTEGER',
]
