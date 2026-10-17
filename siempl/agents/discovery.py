"""RuleDiscoveryAgent – validate sources, import Sigma/Sentinel rules, and generate baseline rules.

Purpose: Three modes of operation:
  1. validate_sources: per source/table check data flow, event rates, gaps, null rates,
     parser column coverage. Reports findings and recommendations.
  2. import_web: fetch Sigma/Sentinel rules matching existing data tables, convert,
     validate against data, and import (disabled by default).
  3. generate: deterministic baseline-based rule ideas from statistical queries on the data.

All modes work deterministically (heuristics/SQL). LLM enrichment optional.

Inputs:  mode (str: "validate_sources", "import_web", "generate")
Outputs: AgentResult with findings, imported rules, or generated rules
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from ..ai.llm import AIBudgetExceeded, AIDisabledError
from ..db import Database
from ..schema import DATA_TABLES, table_columns
from ._discovery_utils import (
    _check_entity_coverage,
    _check_gaps,
    _check_null_rates,
    _count_events_per_table,
    _determine_sourcetype,
    _fetch_sigma_rules,
    _import_or_propose_rule,
    _tables_with_data,
    _validate_imported_rule,
)
from ._injection_hold import record_review_only, scan_value, warning_text
from ._safety import SYSTEM_NOTICE, wrap_untrusted
from .base import Agent, AgentResult

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _validate_source(db: Database, source_id: str) -> dict[str, Any]:
    """Validate data flow and quality for a single source."""
    src = db.query_one("SELECT * FROM sources WHERE source_id=?", [source_id])
    if not src:
        return {"source_id": source_id, "error": "not found"}

    findings: list[dict] = []
    table_events = _count_events_per_table(db, source_id)
    if not table_events:
        findings.append({"level": "warning", "message": "No events found for this source in any table",
                         "recommendation": "Check source configuration and connectivity"})

    findings.extend(_check_gaps(db, source_id, table_events))

    most_events_table = max(table_events, key=table_events.get) if table_events else None
    findings.extend(_check_null_rates(db, source_id, most_events_table))
    findings.extend(_check_entity_coverage(db, source_id, most_events_table))

    sourcetype = _determine_sourcetype(table_events)

    return {
        "source_id": source_id,
        "name": src.get("name", source_id),
        "status": src.get("status", "pending"),
        "parser": src.get("parser"),
        "target_table": src.get("target_table"),
        "sourcetype": sourcetype,
        "tables": table_events,
        "total_events": sum(table_events.values()),
        "findings": findings,
        "finding_count": len(findings),
    }


def _fetch_and_import_rules(db: Database, agent: RuleDiscoveryAgent,
                            http_client=None) -> dict[str, Any]:
    """Fetch Sigma and Sentinel rules, convert, validate, and import."""
    if http_client is None:
        return {"status": "skipped", "reason": "no http_client provided",
                "imported": 0, "skipped": 0, "errors": []}

    results = {"imported": 0, "skipped": 0, "errors": [],
               "imported_rules": [], "skipped_rules": []}

    tables_with_data = _tables_with_data(db)
    if not tables_with_data:
        results["reason"] = "No tables have data; cannot match rules to tables"
        return results

    all_rules = _fetch_sigma_rules(db, tables_with_data, http_client, results)

    existing_refs = {r["source_ref"] for r in db.query(
        "SELECT source_ref FROM rules WHERE source_ref IS NOT NULL AND source_ref != ''")}

    for rule in all_rules:
        skip_reason = _validate_imported_rule(db, rule, existing_refs)
        if skip_reason:
            results["skipped"] += 1
            results["skipped_rules"].append({"name": rule.get("name"), "reason": skip_reason})
            continue
        _import_or_propose_rule(db, agent, rule, results)

    return results


def _generate_baseline_rules(db: Database, agent: RuleDiscoveryAgent) -> list[dict]:
    """Generate deterministic baseline-based rule ideas from statistical queries."""
    generated: list[dict] = []
    now = _utcnow()

    # 1. Rare process by host (ProcessEvents)
    try:
        r = db.query_one(
            'SELECT COUNT(*) as cnt FROM "ProcessEvents" WHERE "TimeGenerated" > ?',
            [now - timedelta(days=7)])
        if r and r["cnt"] and r["cnt"] > 100:
            rule = {
                "name": "Rare Process Execution by Host",
                "description": "A process was observed on a host where it has been seen fewer than 5 times "
                               "in the last 7 days. This is a baseline-based detection for potential "
                               "lateral movement, malware execution, or unauthorized tool usage. "
                               "Low-frequency processes can indicate attacker tradecraft.",
                "triage_steps": (
                    "1. Identify the process name, host, and user from the evidence.\n"
                    "2. Check entity reputation for the process and host.\n"
                    "3. Run: ProcessEvents | where ProcessName == '<process>' and HostName == '<host>' | "
                    "summarize count() by bin(TimeGenerated, 1d)\n"
                    "4. Check if the user has a legitimate reason to run this process.\n"
                    "5. Correlate with network connections from the same host/time window."
                ),
                "severity": "medium",
                "query": (
                    "ProcessEvents\n"
                    "| where TimeGenerated > ago(7d)\n"
                    "| summarize process_count = count() by HostName, ProcessName\n"
                    "| where process_count < 5\n"
                    "| project HostName, ProcessName, process_count"
                ),
                "tables": ["ProcessEvents"],
                "frequency_minutes": 60,
                "lookback_minutes": 10080,  # 7 days
                "threshold": 1,
                "mitre_tactics": ["execution", "lateral_movement"],
                "mitre_techniques": ["T1059", "T1204"],
                "entity_mappings": [
                    {"entity_type": "host", "column": "HostName"},
                    {"entity_type": "process", "column": "ProcessName"},
                ],
                "origin": "ai_generated",
            }
            generated.append(rule)
    except Exception:
        logger.warning("_generate_baseline_rules: ignored error", exc_info=True)

    # 2. Volume spike per source
    for table in ["AuthEvents", "NetworkEvents", "Syslog"]:
        try:
            r = db.query_one(
                f'SELECT COUNT(*) as cnt FROM "{table}" WHERE "TimeGenerated" > ?',
                [now - timedelta(days=7)])
            if r and r["cnt"] and r["cnt"] > 50:
                rule = {
                    "name": f"Unusual Volume Spike in {table}",
                    "description": f"Detects when the {table} event volume exceeds 2 standard deviations "
                                   f"above the 7-day rolling average. Spikes can indicate brute-force attacks, "
                                   f"scanning activity, DDoS, or data exfiltration.",
                    "triage_steps": (
                        f"1. Run: {table} | where TimeGenerated > ago(1h) | summarize count() by SourceId\n"
                        f"2. Identify the source with the spike.\n"
                        "3. Check entity reputation for source IPs/users.\n"
                        "4. Review sample events from the spike period.\n"
                        "5. Correlate with other tables (AuthEvents for login spikes, NetworkEvents for scan spikes)."
                    ),
                    "severity": "low",
                    "query": (
                        f"{table}\n"
                        f"| where TimeGenerated > ago(7d)\n"
                        f"| summarize hourly_count = count() by bin(TimeGenerated, 1h), SourceId\n"
                        f"| summarize avg_count = avg(hourly_count), stdev_count = stdev(hourly_count) by SourceId\n"
                        f"| where avg_count + 2 * stdev_count > 10"
                    ),
                    "tables": [table],
                    "frequency_minutes": 60,
                    "lookback_minutes": 10080,
                    "threshold": 1,
                    "mitre_tactics": ["impact", "command_and_control"],
                    "mitre_techniques": ["T1498", "T1499"],
                    "entity_mappings": [
                        {"entity_type": "host", "column": "HostName"},
                    ],
                    "origin": "ai_generated",
                }
                generated.append(rule)
        except Exception:
            logger.warning("_generate_baseline_rules: ignored error", exc_info=True)

    # 3. First-seen entity logins (AuthEvents)
    try:
        r = db.query_one(
            'SELECT COUNT(*) as cnt FROM "AuthEvents" WHERE "TimeGenerated" > ?',
            [now - timedelta(days=7)])
        if r and r["cnt"] and r["cnt"] > 50:
            rule = {
                "name": "First Seen User Logon from Host",
                "description": "A user logged in from a host they have never used before. "
                               "This baseline detection can reveal compromised credentials, "
                               "lateral movement, or insider threat activity.",
                "triage_steps": (
                    "1. Identify the user and host from evidence.\n"
                    "2. Check entity reputation for both user and host.\n"
                    "3. Run: AuthEvents | where UserName == '<user>' and HostName == '<host>' | "
                    "summarize count() by bin(TimeGenerated, 1d)\n"
                    "4. Check if this is a legitimate new access (new employee, new server, maintenance).\n"
                    "5. Look for other activity from the same user in ProcessEvents and NetworkEvents."
                ),
                "severity": "low",
                "query": (
                    "AuthEvents\n"
                    "| where TimeGenerated > ago(30d) and EventResult == 'success'\n"
                    "| summarize first_seen = min(TimeGenerated) by UserName, HostName\n"
                    "| where first_seen > ago(1d)"
                ),
                "tables": ["AuthEvents"],
                "frequency_minutes": 1440,  # daily
                "lookback_minutes": 43200,  # 30 days
                "threshold": 1,
                "mitre_tactics": ["lateral_movement", "initial_access"],
                "mitre_techniques": ["T1078", "T1021"],
                "entity_mappings": [
                    {"entity_type": "user", "column": "UserName"},
                    {"entity_type": "host", "column": "HostName"},
                ],
                "origin": "ai_generated",
            }
            generated.append(rule)
    except Exception:
        logger.warning("_generate_baseline_rules: ignored error", exc_info=True)

    # 4. LLM-generated rule ideas (optional, AI-enabled)
    try:
        if agent and agent.llm.is_enabled():
            llm_rules = _llm_generate_rules(db, agent)
            generated.extend(llm_rules)
    except (AIDisabledError, AIBudgetExceeded):
        pass

    # Validate and save generated rules
    saved: list[dict] = []
    for rule in generated:
        # Validate KQL
        query_ok = True
        try:
            from ..kql import compile_kql
            compile_kql(rule["query"])
        except Exception:
            query_ok = False

        if not query_ok:
            continue

        # Check deduplication by name
        existing = db.query_one("SELECT rule_id FROM rules WHERE name=?", [rule["name"]])
        if existing:
            continue

        if agent is not None and agent.dry_run:
            payload = {k: rule.get(k) for k in ("name", "description", "triage_steps", "severity", "query", "tables",
                                                "frequency_minutes", "lookback_minutes", "threshold", "mitre_tactics",
                                                "mitre_techniques", "entity_mappings")}
            payload.update({"origin": rule.get("origin", "ai_generated"), "enabled": False})
            agent.recommend("new_rule", rule["name"], f"New rule: {rule['name']}",
                            "Generated from baseline statistics of current data (dry-run: not created).", payload=payload)
            saved.append({"rule_id": None, "name": rule["name"], "origin": rule.get("origin", "ai_generated"), "proposed": True})
            continue

        from ..detect.engine import RuleStore
        rule_id = RuleStore(db).create({**rule, "enabled": False, "origin": rule.get("origin", "ai_generated"),
                                        "frequency_minutes": rule.get("frequency_minutes", 60),
                                        "lookback_minutes": rule.get("lookback_minutes", 10080)})

        saved.append({"rule_id": rule_id, "name": rule["name"],
                      "origin": rule.get("origin", "ai_generated")})

    return saved


def _as_rule_list(data: Any) -> list:
    """LLM JSON mode often wraps the array ({"rules": [...]}) or returns one bare rule object."""
    if isinstance(data, dict):
        return [data] if {"name", "query"} <= set(data) else next((v for v in data.values() if isinstance(v, list)), [])
    return data if isinstance(data, list) else []


def _accepted_rules(data: Any, findings: list[dict]) -> list[dict]:
    """Keep well-formed LLM rule objects. Nothing is accepted when the data held injection findings."""
    if findings:
        return []
    return [r for r in _as_rule_list(data) if isinstance(r, dict) and "name" in r and "query" in r]


def _llm_generate_rules(db: Database, agent: RuleDiscoveryAgent) -> list[dict]:
    """Ask LLM to propose additional rules based on schema + data digest."""
    # Build compact schema + data digest
    digest = {"tables_with_data": {}}
    for table in DATA_TABLES:
        try:
            cnt = db.query_one(f'SELECT COUNT(*) as cnt FROM "{table}"', [])
            if cnt and cnt["cnt"] and cnt["cnt"] > 0:
                cols = [c[0] for c in table_columns(table)]
                # Get sample values for key columns
                samples = {}
                for col in ["EventCode", "EventAction", "EventResult", "HostName",
                            "UserName", "SrcIp"][:5]:
                    if col in cols:
                        try:
                            r = db.query(
                                f'SELECT DISTINCT "{col}" as v FROM "{table}" '
                                f'WHERE "{col}" IS NOT NULL AND "{col}" != \'\' LIMIT 5', [])
                            if r:
                                samples[col] = [x["v"] for x in r]
                        except Exception:
                            logger.debug("_llm_generate_rules: ignored error", exc_info=True)
                digest["tables_with_data"][table] = {
                    "row_count": cnt["cnt"],
                    "columns": cols,
                    "sample_values": samples,
                }
        except Exception:
            logger.debug("_llm_generate_rules: ignored error", exc_info=True)

    prompt = f"""You are a SIEM detection engineer. Given the following table schema and data profile,
propose 2-3 novel KQL detection rules that are NOT baseline rules (first-seen, rare, volume-spike).

## Schema and Data Profile
{wrap_untrusted('digest', digest, 6000)}

## Output Format
Return a JSON array of rule objects:
[
  {{
    "name": "Short descriptive name",
    "description": "What this detects and why it matters. Include common FP causes.",
    "triage_steps": "Numbered triage steps a SOC analyst would follow.",
    "severity": "low|medium|high|critical",
    "query": "Full KQL query with table name and pipes",
    "tables": ["TableName"],
    "mitre_tactics": ["TA0005"],
    "mitre_techniques": ["T1059"],
    "entity_mappings": [{{"entity_type":"user","column":"UserName"}}]
  }}
]

## Rules
- KQL queries MUST use valid table names from the schema
- Only reference columns that exist in those tables
- Use SIMPLE KQL: table name, | where, | project, | summarize, | order by
- Do NOT use | join, | union, | evaluate, | mv-expand
- Only output the JSON array, no other text
"""
    findings = scan_value(digest)  # injection-looking data: LLM rules are not imported
    if findings:
        record_review_only(agent, "discovery", findings)
    prompt += "\n" + SYSTEM_NOTICE + ("\n" + warning_text(findings) if findings else "")
    try:
        resp = agent.ai_chat(
            [{"role": "user", "content": prompt}],
            json_mode=True, max_tokens=3000)
        data = resp.json()
    except Exception:
        return []
    return _accepted_rules(data, findings)


# ── Main agent class ────────────────────────────────────────────────────────────

class RuleDiscoveryAgent(Agent):
    """Validate sources, import rules from Sigma/Sentinel, generate baseline rules."""

    name = "discovery"

    def execute(self, mode: str = "validate_sources", http_client=None, **kw) -> AgentResult:
        result = AgentResult()

        if mode == "validate_sources":
            # Validate all sources
            sources = self.db.query("SELECT source_id FROM sources")
            findings = [_validate_source(self.db, s["source_id"]) for s in sources]

            # Summarize warnings
            warn_count = sum(len(f.get("findings", [])) for f in findings)

            result.output = {"mode": mode, "sources": findings,
                             "total_sources": len(findings),
                             "total_findings": warn_count}
            result.summary = f"Validated {len(findings)} sources, found {warn_count} findings."

        elif mode == "import_web":
            import_results = _fetch_and_import_rules(self.db, self, http_client)
            result.output = {"mode": mode, **import_results}
            result.summary = (f"Import{' (dry-run, ' + str(import_results.get('proposed', 0)) + ' proposed as recommendations)' if self.dry_run else ''}: {import_results['imported']} imported, "
                              f"{import_results['skipped']} skipped, "
                              f"{len(import_results['errors'])} errors.")

        elif mode == "generate":
            saved = _generate_baseline_rules(self.db, self)
            result.output = {"mode": mode, "rules_generated": len(saved),
                             "rules": saved}
            result.summary = (f"Dry-run: proposed {len(saved)} baseline rules as recommendations (nothing created)."
                              if self.dry_run else f"Generated and saved {len(saved)} baseline rules.")

        else:
            return AgentResult(status="error",
                               summary=f"Unknown mode '{mode}'. Valid: validate_sources, import_web, generate")

        return result
