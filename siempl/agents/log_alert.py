"""LogAlertAgent – optional per-line LLM alerting on raw log tables.

WARNING: this agent is a STUB skeleton. The LLM loop is implemented for basic
line-by-line review, but the full pipeline (watermark state, template dedup,
batch-send to cheap model, alert creation) relies on modules from other areas
(detect, kql) that are not yet present. The tests exercise the pipeline with
a fake transport and verify the core logic.

Purpose: read new rows from a configured log table since a stored watermark,
pre-filter cheaply (skip lines matching allowlist, deduplicate repeated templates),
batch to the cheap model for suspicious-line detection, and create alerts via the
detect pathway for flagged lines.

Inputs:  table (str), limit (int, default 50), table_filter (KQL str, optional)
Outputs: AgentResult with alert_ids created, lines_processed, lines_flagged

Failure modes:
  - log_alert_agent_enabled is False -> skipped
  - AI disabled -> skipped (this agent has no heuristic fallback; it is LLM-only)
  - Budget exceeded -> partial results
  - No new rows -> ok, zero results
  - detect module missing -> alerts can't be created, logged as error
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime

from ..ai.llm import AIBudgetExceeded, AIDisabledError
from ..db import new_id
from ._injection_hold import record_review_only, scan_value, warning_text
from ._safety import LOG_FLAG_SEVERITIES, REASON_CAP, SYSTEM_NOTICE, clean_text, findings_for_output, wrap_untrusted
from .base import Agent, AgentResult


def _flagged_rows(parsed: list, templates: dict[str, list[dict]]) -> list[dict]:
    """Map the model's flags back to rows. Strict: known template keys, allowed severities, capped reasons."""
    out: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict) or item.get("suspicious") is not True:
            continue
        tkey = item.get("template_key")
        if not isinstance(tkey, str) or tkey not in templates:
            continue
        sev = item.get("severity")
        sev = sev if sev in LOG_FLAG_SEVERITIES else "low"
        note = clean_text(str(item.get("reason", "")))[:REASON_CAP]
        out.extend({**dict(r), "ai_note": note, "ai_severity": sev} for r in templates[tkey])
    return out


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ---- Template normalisation for dedup -----------------------------------------


def _normalise_template(text: str) -> str:
    """Replace digits and hex strings with placeholders for template matching.

    "Failed password for root from 192.168.1.1 port 22"
    -> "Failed password for root from <IP> port <NUM>"
    """
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', text)
    text = re.sub(r'\b[0-9a-fA-F]{8,}\b', '<HEX>', text)     # hashes, UUIDs
    text = re.sub(r'\b\d{4,}\b', '<NUM>', text)               # long numbers (timestamps, PIDs)
    text = re.sub(r'\b\d+\b', '<NUM>', text)                  # shorter numbers
    return text


def _template_key(text: str) -> str:
    """Return a stable key for a template (SHA256 of normalised text)."""
    return hashlib.sha256(_normalise_template(text).encode()).hexdigest()[:12]


# ---- LogAlertAgent -------------------------------------------------------------


class LogAlertAgent(Agent):
    """Periodic agent that scans log tables for suspicious lines using a cheap LLM.

    Off by default (settings['log_alert_agent_enabled']). Reads new rows since a
    stored watermark, deduplicates by template, batches to the cheap model, and
    creates alerts for flagged lines.
    """

    name = "log_alert"

    def execute(self, table: str = "", limit: int = 50,
                table_filter: str = "", **kw) -> AgentResult:
        """Execute one scan cycle.

        Args:
            table: Data table name to scan (e.g. 'Syslog', 'AuthEvents').
            limit: Max lines to read this run.
            table_filter: Optional KQL where-clause to pre-filter.
        """
        if not table:
            return AgentResult(status="error", summary="table name is required")

        enabled = self.db.get_setting("log_alert_agent_enabled", False)
        if not enabled:
            return AgentResult(status="skipped",
                               summary="log_alert_agent_enabled is False",
                               output={"table": table})

        result = AgentResult()
        result.output["table"] = table
        result.output["alert_ids"] = []

        # 1. Get watermark (last seen TimeGenerated for this table)
        watermark_key = f"log_alert_watermark_{table}"
        watermark = self.db.get_setting(watermark_key, None)
        if watermark is None:
            watermark = "1970-01-01T00:00:00"

        # 2. Read new rows
        rows = self._read_new_rows(table, watermark, limit, table_filter)
        result.output["lines_read"] = len(rows)

        if not rows:
            result.summary = f"no new rows in {table}"
            return result

        # 3. Pre-filter: skip allowlisted patterns
        allowlist = self._get_allowlist()
        filtered = self._apply_allowlist(rows, allowlist)
        result.output["lines_after_allowlist"] = len(filtered)

        if not filtered:
            result.summary = f"all {len(rows)} rows filtered by allowlist"
            # Update watermark anyway
            last_ts = max(r.get("TimeGenerated", "") for r in rows)
            if hasattr(last_ts, "isoformat"):
                last_ts = last_ts.isoformat()
            self.db.set_setting(watermark_key, str(last_ts))
            return result

        # 4. Deduplicate by template
        deduped = self._deduplicate_templates(filtered)
        result.output["unique_templates"] = len(deduped)
        self.findings = scan_value(deduped)  # before the LLM sees any template
        result.output["lines_after_dedup"] = sum(len(v) for v in deduped.values())

        # 5. Run LLM batch analysis (if AI enabled)
        try:
            flagged = self._llm_analyze_batch(deduped, result)
        except AIDisabledError:
            result.summary = "AI disabled; log_alert requires LLM"
            result.status = "skipped"
            return result
        except AIBudgetExceeded:
            result.summary = "budget exceeded; partial results"
            result.status = "ok"
            flagged = []

        result.output["lines_flagged"] = len(flagged)

        # 6. Create alerts for flagged lines
        if self.findings:
            record_review_only(self, table, self.findings)
            flagged = []  # downgraded: no automatic alerts while the batch looks injected
            result.output.update(injection_detected=True,
                                 findings=findings_for_output(self.findings))
        if flagged:
            alert_ids = self._create_alerts(table, flagged, result)
            result.output["alert_ids"] = alert_ids

        # 7. Update watermark
        self._advance_watermark(rows, watermark_key)

        result.summary = (f"scanned {len(rows)} rows, {len(deduped)} unique templates, "
                          f"flagged {len(flagged)} lines, created {len(result.output['alert_ids'])} alerts")
        return result

    # -- private helpers -------------------------------------------------------
    def _advance_watermark(self, rows: list[dict], watermark_key: str) -> None:
        """Store the newest TimeGenerated as ISO text so the next run starts after it."""
        if not rows:
            return
        last_ts = max(r.get("TimeGenerated", "") for r in rows)
        if hasattr(last_ts, "isoformat"):
            last_ts = last_ts.isoformat()
        self.db.set_setting(watermark_key, str(last_ts))


    def _read_new_rows(self, table: str, watermark: str, limit: int,
                       table_filter: str) -> list[dict]:
        """Read new rows from the table since watermark."""
        q = f'SELECT * FROM "{table}" WHERE TimeGenerated > ?'
        params: list = [watermark]
        if table_filter:
            q += f" AND ({table_filter})"
        q += " ORDER BY TimeGenerated ASC LIMIT ?"
        params.append(limit)
        return self.db.query(q, params)

    def _get_allowlist(self) -> list[str]:
        """Load allowlist patterns from settings."""
        raw = self.db.get_setting("log_alert_allowlist", [])
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = []
        return raw if isinstance(raw, list) else []

    def _apply_allowlist(self, rows: list[dict], allowlist: list[str]) -> list[dict]:
        """Filter out rows matching any allowlist pattern (substring match on Message)."""
        if not allowlist:
            return rows
        return [r for r in rows
                if not any(p.lower() in (r.get("Message") or "").lower()
                          for p in allowlist)]

    def _deduplicate_templates(
        self, rows: list[dict]
    ) -> dict[str, list[dict]]:
        """Group rows by normalised template key. Returns {template_key: [rows]}."""
        groups: dict[str, list[dict]] = {}
        for r in rows:
            msg = r.get("Message") or ""
            key = _template_key(msg)
            groups.setdefault(key, []).append(r)
        return groups

    def _llm_analyze_batch(self, templates: dict[str, list[dict]],
                           result: AgentResult) -> list[dict]:
        """Send deduplicated template samples to cheap model for analysis.

        Returns list of flagged rows (original row dicts with added ai_note/ai_severity).
        """
        flagged: list[dict] = []

        # Build prompt with one sample per template, including count
        samples: list[dict] = []
        for tkey, rows in templates.items():
            sample = rows[0]
            samples.append({
                "template_key": tkey,
                "count": len(rows),
                "sample": {k: sample[k] for k in
                           ["TimeGenerated", "HostName", "UserName", "SrcIp",
                            "Message", "EventCode", "EventAction"]
                           if k in sample},
            })

        if not samples:
            return flagged

        system_prompt = (
            "You are a log analysis assistant. Review the following log line templates "
            "and flag any that appear suspicious (security-relevant). "
            "Respond with a JSON array of objects, each with:\n"
            "- template_key: the key from the input\n"
            "- suspicious: true/false\n"
            "- reason: short explanation (max 80 chars)\n"
            "- severity: one of informational, low, medium, high\n"
            "Only flag lines that are genuinely suspicious. A line about cron or systemd "
            "starting a service is NOT suspicious. A line about a failed login, root access, "
            "or command execution IS suspicious.\n"
            "Do NOT flag more than 20% of lines. Be conservative."
        )

        system_prompt += "\n\n" + SYSTEM_NOTICE + ("\n" + warning_text(self.findings) if self.findings else "")
        user_content = wrap_untrusted("log_templates", samples, 12000)

        try:
            resp = self.ai_chat(
                [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                model=self.db.get_setting("ai_cheap_model"),
                max_tokens=2000,
                json_mode=True,
            )
        except (AIDisabledError, AIBudgetExceeded):
            raise

        # Parse response
        parsed = None
        try:
            parsed = resp.json()
        except json.JSONDecodeError:
            # Try code-fence extraction
            text = resp.text
            m = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
            if m:
                try:
                    parsed = json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass

        if not isinstance(parsed, list):
            result.output["llm_parse_error"] = resp.text[:200]
            return flagged

        # Map back to original rows
        flagged.extend(_flagged_rows(parsed, templates))

        return flagged

    def _create_alerts(self, table: str, flagged: list[dict],
                       result: AgentResult) -> list[str]:
        """Create alerts for flagged log lines. Returns list of alert_ids."""
        alert_ids: list[str] = []
        # Group by template for one alert per template
        by_template: dict[str, list[dict]] = {}
        for r in flagged:
            tkey = _template_key(r.get("Message", ""))
            by_template.setdefault(tkey, []).append(r)

        for tkey, rows in by_template.items():
            sample = rows[0]
            severity = sample.get("ai_severity", "low")
            description = (f"Log Alert Agent flagged {len(rows)} lines in {table}: "
                           f"{sample.get('ai_note', 'no reason')}")
            title = f"Log alert: {sample.get('ai_note','suspicious log pattern')[:60]}"

            # Build entity list
            entities: list[dict] = []
            for col, etype in [("UserName", "user"), ("HostName", "host"),
                               ("SrcIp", "ip"), ("DstIp", "ip"),
                               ("ProcessName", "process")]:
                val = sample.get(col)
                if val and not any(e["value"] == val for e in entities):
                    entities.append({"type": etype, "value": str(val)})

            # Try to create through detect module
            alert_id = None
            try:
                from ..detect import create_alert
                rule = {
                    "rule_id": "ai_log_agent",
                    "name": "AI Log Alert Agent",
                    "severity": severity,
                    "description": description,
                    "triage_steps": "Review flagged log lines in evidence. Check surrounding context.",
                    "origin": "ai_generated",
                    "enabled": False,  # disabled-from-scheduler
                    "tables": [table],
                    "query": f'{table} | where 1==1',  # placeholder
                }
                evidence_cols = [c for c in sample if not c.startswith("ai_")]
                evidence = [{c: r.get(c) for c in evidence_cols} for r in rows[:10]]
                alert_id = create_alert(self.db, rule, evidence, evidence_cols)
            except ImportError:
                # Direct insert fallback
                alert_id = new_id("al_")
                self.db.execute(
                    """INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,
                       evidence,entities,created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    [alert_id, "ai_log_agent", title, severity, "new",
                     description, json.dumps(rows[:10], default=str),
                     json.dumps(entities), _utcnow(), _utcnow()])

            if alert_id:
                alert_ids.append(alert_id)
                self.record_action(result, "create_alert",
                                   alert_id=alert_id, table=table,
                                   count=len(rows))

        return alert_ids
