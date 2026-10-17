"""TriageAgent – L1 SOC triage for a single alert. See docs/AGENTS.md for the full design.

Purpose: given an alert_id, gather deterministic context (alert, rule, evidence, entities,
related alerts), then either run a tool-using LLM loop (AI enabled) or apply a heuristic
pre-triage (AI disabled). Produce a verdict and (per policy) close, escalate, or comment.

Inputs:  alert_id (str)
Outputs: AgentResult with verdict details in result.output

Failure modes:
  - alert_id not found -> error
  - AI disabled -> deterministic heuristic path
  - AI budget exceeded -> fall back to heuristic
  - LLM returns unparseable JSON -> needs_human verdict
  - LLM step cap (6) reached -> needs_human verdict
  - Policy mode 'off' -> skipped
"""

from __future__ import annotations

import json

# Paths relative to this file
import os as _os
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from ..ai.llm import AIBudgetExceeded, AIDisabledError, LLMClient
from ..alerts_status import set_status
from ..db import Database, new_id
from ._injection_hold import merge_findings, record_injection_hold, scan_alert_inputs, scan_tool_result, warning_text
from ._safety import (
    SYSTEM_NOTICE,
    build_entity_kql,
    disposition_with_findings,
    findings_for_output,
    validate_verdict,
    wrap_untrusted,
)
from ._triage_heuristics import heuristic_verdict
from .base import SEVERITY_ORDER, Agent, AgentResult, Policy, resolve_policy

_PROMPT_DIR = _os.path.join(_os.path.dirname(__file__), "prompts")
with open(_os.path.join(_PROMPT_DIR, "triage_system.md")) as _f:
    TRIAGE_SYSTEM_PROMPT = _f.read()
with open(_os.path.join(_PROMPT_DIR, "triage_tools.md")) as _f:
    TRIAGE_TOOLS_PROMPT = _f.read()
with open(_os.path.join(_PROMPT_DIR, "triage_verdict_schema.md")) as _f:
    TRIAGE_VERDICT_SCHEMA = _f.read()

MAX_LLM_STEPS = 6
DEFAULT_CLOSE_CONFIDENCE = 0.85
QUERY_ROW_CAP = 2000


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ---- Tool implementation helpers (deterministic, read-only) --------------------

def _run_kql_tool(db: Database, query: str) -> dict[str, Any]:
    """Run a read-only KQL query with a row cap. Returns a dict result the LLM can read."""
    try:
        from ..kql import KqlError, compile_kql
        from ..kql import run_kql as _kql_run
    except ImportError:
        return {"error": "KQL module not available", "columns": [], "rows": [], "truncated": False}
    try:
        compile_kql(query)
        result = _kql_run(db, query, limit=QUERY_ROW_CAP, origin="agent", log=False)
        return {
            "columns": result.columns,
            "rows": result.rows[:50],  # only first 50 to LLM; rest available if needed
            "truncated": result.truncated,
            "total_rows": len(result.rows),
            "elapsed_ms": result.elapsed_ms,
        }
    except KqlError as e:
        return {"error": str(e), "columns": [], "rows": [], "truncated": False}


def _get_entity_tool(db: Database, etype: str, value: str) -> dict[str, Any]:
    """Look up an entity from the DB."""
    key = f"{etype}:{value.lower()}"
    row = db.query_one("SELECT * FROM entities WHERE entity_id=?", [key])
    if row:
        return dict(row)
    return {"entity_id": key, "type": etype, "value": value, "found": False,
            "reputation": 50, "note": "entity not in store"}


def _get_related_alerts_tool(db: Database, entity_id: str) -> list[dict[str, Any]]:
    """Return recent alerts involving the given entity."""
    rows = db.query(
        """SELECT a.alert_id, a.title, a.severity, a.verdict, a.created_at, a.rule_id
           FROM alerts a
           WHERE a.created_at > ? AND a.entities LIKE ?
           ORDER BY a.created_at DESC LIMIT 50""",
        [_utcnow() - timedelta(days=90), f"%{entity_id}%"])
    return rows


def _lookup_ip_reputation_tool(db: Database, ip: str) -> dict[str, Any]:
    """Stub: read from local entity store only. Extension point for external TI."""
    return _get_entity_tool(db, "ip", ip)


# ---- Deterministic heuristic fallback -----------------------------------------

def _heuristic_triage(db: Database, alert: dict, rule: dict | None,
                      entities: list[dict]) -> dict[str, Any]:
    """Rules-based pre-triage when AI is disabled. Logic: _triage_heuristics.heuristic_verdict."""
    return heuristic_verdict(db, alert, rule, entities)


# ---- LLM tool schema (OpenAI-compatible function calling) ----------------------

def _tool_definitions() -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": "run_kql",
                "description": "Run a read-only KQL query against event tables. Row cap: 2000.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string",
                                  "description": "KQL query starting with table name and | where"}
                    },
                    "required": ["query"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_entity",
                "description": "Look up an entity by type and value.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string",
                                 "enum": ["user", "host", "ip", "process", "file_hash", "domain"]},
                        "value": {"type": "string"},
                    },
                    "required": ["type", "value"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_related_alerts",
                "description": "Get recent alerts involving the given entity_id.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "entity_id": {"type": "string"},
                    },
                    "required": ["entity_id"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "lookup_ip_reputation",
                "description": "Look up IP reputation from local entity store (stub; external TI not implemented).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                    },
                    "required": ["ip"],
                },
            },
        },
    ]


# ---- JSON extraction (robust against code fences, garbage) ---------------------

def _extract_json(text: str) -> dict | None:
    """Robustly extract a JSON object from LLM text. Returns None if unparseable."""
    if not text:
        return None
    # Try to find code-fenced JSON
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    # Try to find a bare JSON object
    else:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            text = m.group(0)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _tool_args(raw: Any) -> dict[str, str]:
    """Parse tool-call arguments. Malformed input becomes {}; values are coerced to text."""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, RecursionError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): ("" if v is None else str(v)) for k, v in data.items()}


def _run_tool(db: Database, name: str, args: dict[str, str]) -> Any:
    """Dispatch one read-only tool call. Unknown tool names return None."""
    handlers = {
        "run_kql": lambda: _run_kql_tool(db, args.get("query", "")),
        "get_entity": lambda: _get_entity_tool(db, args.get("type", ""), args.get("value", "")),
        "get_related_alerts": lambda: _get_related_alerts_tool(db, args.get("entity_id", "")),
        "lookup_ip_reputation": lambda: _lookup_ip_reputation_tool(db, args.get("ip", "")),
    }
    handler = handlers.get(name)
    return handler() if handler else None


def _validated_monitor_entities(db: Database, entities: list[dict],
                                alert_entity_ids: list[str]) -> list[dict]:
    """Keep monitor entities the alert or the entity store already knows. Unknown ones are dropped."""
    known = set(alert_entity_ids)
    kept = []
    for e in entities:
        eid = f"{e.get('type', '')}:{str(e.get('value', '')).lower()}"
        if eid in known or db.query_one("SELECT 1 AS ok FROM entities WHERE entity_id=?", [eid]):
            kept.append(e)
    return kept


# ---- Main agent ----------------------------------------------------------------

class TriageAgent(Agent):
    """Investigate a single alert and produce a verdict."""

    name = "triage"

    def __init__(self, db: Database, llm: LLMClient | None = None, dry_run: bool | None = None):
        super().__init__(db, llm, dry_run)
        self.step_count = 0
        self.findings: list[dict] = []

    # -- context gathering (deterministic) ------------------------------------
    def _gather_context(self, alert_id: str) -> tuple[dict | None, dict | None, str]:
        """Gather alert, rule, evidence, entities. Returns (alert, rule, error)."""
        alert = self.db.query_one("SELECT * FROM alerts WHERE alert_id=?", [alert_id])
        if not alert:
            return None, None, f"alert {alert_id} not found"

        rule = self.db.query_one("SELECT * FROM rules WHERE rule_id=?", [alert.get("rule_id", "")])

        # Parse evidence rows from alert.evidence JSON
        evidence = []
        try:
            raw = alert.get("evidence")
            if isinstance(raw, str):
                evidence = json.loads(raw) if raw else []
            elif isinstance(raw, list):
                evidence = raw
        except json.JSONDecodeError:
            evidence = []

        # Gather entity records from alert.entities JSON
        entity_records: list[dict] = []
        entity_ids: list[str] = []
        try:
            raw_entities = alert.get("entities")
            if isinstance(raw_entities, str):
                ent_list = json.loads(raw_entities) if raw_entities else []
            elif isinstance(raw_entities, list):
                ent_list = raw_entities
            else:
                ent_list = []
        except json.JSONDecodeError:
            ent_list = []

        for e in ent_list:
            eid = f"{e.get('type','')}:{e.get('value','').lower()}"
            entity_ids.append(eid)
            row = self.db.query_one("SELECT * FROM entities WHERE entity_id=?", [eid])
            if row:
                entity_records.append(dict(row))

        # Related alerts (first 20 across all alert entities)
        related_alerts: list[dict] = []
        for eid in entity_ids[:5]:
            related_alerts.extend(_get_related_alerts_tool(self.db, eid))

        # Deduplicate by alert_id
        seen = set()
        related_alerts = [a for a in related_alerts if not (a["alert_id"] in seen or seen.add(a["alert_id"]))][:20]

        context = {
            "alert": alert,
            "rule": rule,
            "evidence_rows": evidence[:20],
            "entities": entity_records,
            "entity_ids": entity_ids,
            "related_alerts": related_alerts,
        }
        return alert, context, ""

    # -- LLM tool loop --------------------------------------------------------
    def _llm_tool_loop(self, alert: dict, rule: dict | None, context: dict,
                       policy: Policy) -> dict[str, Any]:
        """Run the tool-using LLM loop (max N steps). Returns verdict dict."""
        self.step_count = 0

        # Build system message
        rule_desc = wrap_untrusted("rule", (rule.get("description") or "No description") if rule else "No rule found", 2000)
        triage_steps = wrap_untrusted("triage_steps", (rule.get("triage_steps") or "No triage steps") if rule else "No triage steps", 2000)
        system_content = TRIAGE_SYSTEM_PROMPT + "\n\n" + SYSTEM_NOTICE + "\n\n## Current Alert\n"
        system_content += f"Alert ID: {alert['alert_id']}\n"
        system_content += f"Title: {wrap_untrusted('title', alert.get('title', ''), 300)}\n"
        system_content += f"Severity: {wrap_untrusted('severity', alert.get('severity', 'medium'), 40)}\n"
        system_content += f"Rule: {rule_desc}\n"
        system_content += f"Triage Steps: {triage_steps}\n\n"
        if self.findings:
            system_content += warning_text(self.findings) + "\n\n"
        system_content += TRIAGE_TOOLS_PROMPT + "\n\n"
        system_content += TRIAGE_VERDICT_SCHEMA

        messages: list[dict] = [{"role": "system", "content": system_content}]

        # First user message: the evidence
        sections = {
            "alert": {k: alert[k] for k in ["alert_id", "title", "severity", "description",
                                              "created_at", "row_count"]
                       if k in alert},
            "evidence_rows": context.get("evidence_rows", []),
            "entities": context.get("entities", []),
            "related_alerts": context.get("related_alerts", []),
        }
        evidence_text = "\n".join(f"## {k}\n{wrap_untrusted(k, v, 8000)}" for k, v in sections.items())
        messages.append({"role": "user", "content": evidence_text})

        tools = _tool_definitions()

        for step_idx in range(MAX_LLM_STEPS):
            self.step_count = step_idx + 1
            last_step = step_idx == MAX_LLM_STEPS - 1
            if last_step:
                # Final turn: no more tools, force a committed verdict (otherwise a busy
                # investigation ends in a useless step_cap needs_human).
                messages.append({"role": "user", "content":
                                 "Investigation budget exhausted. Do NOT call any more tools. "
                                 "Based on the evidence gathered so far, output your final verdict "
                                 "as the JSON object now (verdict, confidence, summary, "
                                 "recommended_actions...). If uncertain, lower the confidence "
                                 "or use needs_human, but state your best assessment."})
            try:
                resp = self.ai_chat(messages) if last_step else self.ai_chat(messages, tools=tools)
            except (AIDisabledError, AIBudgetExceeded):
                return _heuristic_triage(self.db, alert, rule, context.get("entities", []))

            text = resp.text
            tool_calls = resp.tool_calls

            # If no tool calls, try to extract verdict
            if not tool_calls:
                verdict = _extract_json(text)
                if verdict and "verdict" in verdict:
                    return {**validate_verdict(verdict), "source": "llm"}
                # No verdict yet: ask to produce one
                messages.append({"role": "assistant", "content": text})
                messages.append({"role": "user",
                                 "content": "Please produce your verdict as a JSON object now. "
                                            "Include all required fields from the schema."})
                continue

            # Process tool calls
            messages.append({"role": "assistant", "content": text,
                             "tool_calls": tool_calls})
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args = _tool_args(fn.get("arguments", "{}"))

                result = _run_tool(self.db, name, args)

                self.findings = merge_findings(self.findings, scan_tool_result(result))
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{step_idx}"),
                    "content": wrap_untrusted(f"tool_{name}", result, 8000),
                })

        # Step cap reached
        return {
            "verdict": "needs_human",
            "confidence": 0.30,
            "severity_adjustment": None,
            "summary": f"LLM did not produce a verdict within {MAX_LLM_STEPS} steps.",
            "evidence_refs": [],
            "recommended_actions": ["Escalate for manual triage"],
            "monitor_entities": [],
            "monitor_patterns": [],
            "source": "step_cap_reached",
        }

    # -- main execute ----------------------------------------------------------
    def execute(self, alert_id: str = "", **kw) -> AgentResult:
        if not alert_id:
            return AgentResult(status="error", summary="alert_id is required")

        # Resolve policy
        policy = resolve_policy(self.db, "triage",
                                severity=kw.get("severity"),
                                rule_id=kw.get("rule_id"))
        if policy.mode == "off":
            return AgentResult(status="skipped",
                               summary="triage policy mode is 'off'",
                               output={"alert_id": alert_id, "policy_mode": "off"})

        result = AgentResult()
        alert, context, err = self._gather_context(alert_id)
        if err:
            result.status = "error"
            result.summary = err
            return result

        self.findings = scan_alert_inputs(alert, context)  # before any LLM or heuristic runs
        try:
            verdict = self._llm_tool_loop(alert, context.get("rule"), context, policy)
        except AIDisabledError:
            verdict = _heuristic_triage(self.db, alert, context.get("rule"),
                                        context.get("entities", []))
        except AIBudgetExceeded:
            verdict = _heuristic_triage(self.db, alert, context.get("rule"),
                                        context.get("entities", []))

        verdict["monitor_entities"] = _validated_monitor_entities(
            self.db, verdict.get("monitor_entities", []), context.get("entity_ids", []))
        if self.findings:
            verdict = disposition_with_findings(verdict, self.findings)
            record_injection_hold(self, result, alert_id, self.findings)
            result.summary = f"verdict=needs_human injection held dry_run={self.dry_run}"
        else:
            self._apply_verdict(result, alert, verdict, policy)

        result.output.update({
            "alert_id": alert_id,
            "verdict": verdict.get("verdict"),
            "confidence": verdict.get("confidence"),
            "severity_adjustment": verdict.get("severity_adjustment"),
            "summary": verdict.get("summary", ""),
            "evidence_refs": verdict.get("evidence_refs", []),
            "recommended_actions": verdict.get("recommended_actions", []),
            "monitor_entities": verdict.get("monitor_entities", []),
            "monitor_patterns": verdict.get("monitor_patterns", []),
            "source": verdict.get("source", "llm"),
            "steps_used": self.step_count,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "cost_usd": self.cost,
            "injection_detected": bool(self.findings),
        })
        if self.findings:
            result.output.update(findings=findings_for_output(self.findings),
                                 model_verdict=verdict.get("model_verdict"))
        return result

    # -- policy-driven side effects -------------------------------------------
    def _apply_verdict(self, result: AgentResult, alert: dict,
                       verdict: dict, policy: Policy) -> None:
        """Apply verdict per policy. All mutations guarded by dry_run."""
        mode = policy.mode
        v = verdict.get("verdict", "needs_human")
        confidence = verdict.get("confidence", 0.0)
        severity = (alert.get("severity") or "medium").lower()
        severity_idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 3

        # Always comment (unless mode is 'off', which is already handled)
        if mode in ("recommend", "monitor", "auto_close", "auto_remediate"):
            self._add_alert_comment(result, alert["alert_id"], verdict)

        # Monitor mode: may create temp rules
        if mode in ("monitor", "auto_close", "auto_remediate"):
            self._maybe_create_temp_rules(result, verdict, policy)

        # Auto-close logic
        close_threshold = float(self.db.get_setting("triage_close_confidence",
                                                     DEFAULT_CLOSE_CONFIDENCE))
        if mode in ("auto_close", "auto_remediate") and policy.can_close:
            if v in ("false_positive", "benign") and confidence >= close_threshold:
                self._close_alert(result, alert, verdict)
            elif v == "true_positive" and confidence >= close_threshold:
                # True positive: escalate if high severity, else close
                if severity_idx >= 3 or (severity_idx >= 2 and confidence < 0.90):
                    self._escalate_alert(result, alert, verdict, policy)
                else:
                    self._close_alert(result, alert, verdict)
            elif severity_idx >= 3 and policy.can_escalate:
                self._escalate_alert(result, alert, verdict, policy)
            elif confidence < 0.70:
                self._escalate_alert(result, alert, verdict, policy)

        # Auto-remediate extras
        if mode == "auto_remediate" and policy.can_remediate and v == "true_positive":
            self.record_action(result, "would_auto_remediate",
                               alert_id=alert["alert_id"],
                               actions=verdict.get("recommended_actions", []))

        result.summary = f"verdict={v} conf={confidence:.2f} mode={mode} dry_run={self.dry_run}"

    def _add_alert_comment(self, result: AgentResult, alert_id: str,
                           verdict: dict) -> None:
        body = f"[agent:triage] verdict={verdict.get('verdict')} "
        body += f"confidence={verdict.get('confidence',0):.2f}. "
        body += verdict.get("summary", "")[:500]
        if self.dry_run:
            self.record_action(result, "add_comment", alert_id=alert_id, body=body[:100])
        else:
            self.db.execute(
                "INSERT INTO alert_comments(comment_id,alert_id,author,body) VALUES (?,?,?,?)",
                [new_id("cm_"), alert_id, "agent:triage", body])

    def _close_alert(self, result: AgentResult, alert: dict,
                     verdict: dict) -> None:
        v = verdict.get("verdict", "benign")
        if self.dry_run:
            self.record_action(result, "close_alert", alert_id=alert["alert_id"],
                               verdict=v, verdict_by="agent:triage")
        else:
            status = "closed_tp" if v == "true_positive" else "closed_fp"
            set_status(self.db, alert["alert_id"], status, "agent:triage")

    def _escalate_alert(self, result: AgentResult, alert: dict,
                        verdict: dict, policy: Policy) -> None:
        if not policy.can_escalate:
            return
        if self.dry_run:
            self.record_action(result, "escalate_alert", alert_id=alert["alert_id"])
        else:
            set_status(self.db, alert["alert_id"], "active", "agent:triage")

    def _maybe_create_temp_rules(self, result: AgentResult, verdict: dict,
                                 policy: Policy) -> None:
        """Create temporary monitoring rules from verdict output."""
        if not policy.can_create_temp_rules:
            return

        # Only validated entities. Model-written KQL (monitor_patterns) is never executed.
        entities = verdict.get("monitor_entities", [])
        for e in entities[:3]:
            etype = e.get("type", "")
            value = e.get("value", "")
            reason = "monitor entity"
            kql = build_entity_kql(etype, value)
            if not kql:
                continue
            try:
                from ..kql import KqlError, compile_kql
                compile_kql(kql)
            except (ImportError, KqlError):
                continue

            rule_id = new_id("ai_tmp_")
            expires = _utcnow() + timedelta(hours=24)
            if self.dry_run:
                self.record_action(result, "create_temp_rule",
                                   rule_id=rule_id, kql=kql, reason=reason,
                                   expires_at=str(expires))
            else:
                self._insert_temp_rule(rule_id, kql, reason, expires, verdict)

    def _insert_temp_rule(self, rule_id: str, kql: str, reason: str,
                          expires: datetime, verdict: dict) -> None:
        """Insert a temporary monitoring rule. Uses RuleStore if available, else direct."""
        try:
            from ..detect import RuleStore
            rs = RuleStore(self.db)
            rs.create({
                "rule_id": rule_id,
                "name": f"AI temp: {reason[:80]}",
                "description": f"Auto-created by triage agent. Verdict: {verdict.get('verdict')}. {reason}",
                "triage_steps": "Auto-created monitoring rule. Review after expiry.",
                "severity": "low",
                "query": kql,
                "tables": ["GenericEvents"],
                "frequency_minutes": 5,
                "lookback_minutes": 5,
                "threshold": 1,
                "origin": "ai_temporary",
                "expires_at": expires,
                "enabled": True,
            })
        except ImportError:
            # Direct insert into rules table
            self.db.execute(
                """INSERT INTO rules(rule_id,name,description,triage_steps,severity,query,tables,
                   frequency_minutes,lookback_minutes,threshold,origin,expires_at,enabled)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [rule_id, f"AI temp: {reason[:80]}",
                 f"Auto-created by triage agent. {reason}", "Auto-created monitoring rule.",
                 "low", kql, json.dumps(["GenericEvents"]), 5, 5, 1,
                 "ai_temporary", expires, True])


# ---- Scheduler entry point -----------------------------------------------------

def triage_new_alerts(db: Database, limit: int = 20) -> list[AgentResult]:
    """Entry point for the agent scheduler. Triages up to `limit` new alerts.

    Respects policy mode 'off' (skips all) and AI disabled (heuristic only).
    Returns list of AgentResult for each alert triaged.
    """
    policy = resolve_policy(db, "triage")
    if policy.mode == "off":
        return []

    alerts = db.query(
        "SELECT * FROM alerts WHERE status='new' ORDER BY created_at ASC LIMIT ?",
        [limit])
    results: list[AgentResult] = []
    for alert in alerts:
        agent = TriageAgent(db)
        res = agent.run(input_ref=alert["alert_id"], alert_id=alert["alert_id"])
        results.append(res)
    return results
