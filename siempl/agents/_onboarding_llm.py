"""LLM-assisted mapping-spec helpers for OnboardingAgent.

Functions take the agent as an argument; OnboardingAgent is imported under TYPE_CHECKING only
to avoid an import cycle. Moved out of onboarding.py to keep that module under its size ratchet.
Behavior is unchanged.
"""
from __future__ import annotations

import copy
import json
import logging
from typing import TYPE_CHECKING

from ..ai.llm import AIBudgetExceeded, AIDisabledError
from ..ingest.mapping import validate_spec
from ..schema import DATA_TABLES, table_columns
from ._injection_hold import warning_text
from ._safety import SYSTEM_NOTICE, wrap_untrusted

if TYPE_CHECKING:
    from .onboarding import OnboardingAgent

# Logger name kept as the original module's so log records and filters are unchanged.
logger = logging.getLogger("siempl.agents.onboarding")


# ── helper: LLM spec proposal ──────────────────────────────────────────────────

def _llm_propose_spec(agent: OnboardingAgent, source_name: str,
                      analysis: dict, samples: list[str]) -> dict | None:
    """Ask the LLM to propose a mapping spec. Returns None on failure."""
    # Compact schema digest
    schema_digest = {t: [c[0] for c in table_columns(t)] for t in DATA_TABLES}

    sample_digest = samples[:5]  # only send first 5
    sample_text = wrap_untrusted("samples", [str(s)[:500] for s in sample_digest], 3000)

    prompt = f"""You are a SIEM log onboarding assistant. Given sample log records and the available
database schema, produce a declarative mapping parser spec as a JSON object.

## Available Tables and Columns
{json.dumps(schema_digest, indent=2)}

## Structure Analysis
- Detected format: {analysis.get('format', 'json')}
- Common field keys: {json.dumps(analysis.get('json_keys', analysis.get('keys', {})))}
- Field examples: {wrap_untrusted('field_examples', analysis.get('field_examples', {}), 2000)}

## Sample Records (first 5)
{sample_text}

## Instructions
Produce a JSON object that follows the MappingParser spec format:
{{
  "name": "parser_{source_name[:20]}",
  "description": "Auto-generated parser for {source_name}",
  "format": "json|regex|kv|csv",
  "target_table": "AuthEvents|ProcessEvents|NetworkEvents|WebAccess|FileEvents|Syslog|GenericEvents",
  "time": {{"field": "$.timestamp_field", "format": "iso8601"}},
  "fields": {{
    "ColumnName": "$.path.to.field",
    "SrcIp": {{"path": "$.client.ip", "transform": "lower"}}
  }},
  "constants": {{"SourceType": "{source_name}"}},
  "when": {{}}
}}

## Rules
- Column names MUST match exactly from the schema above
- target_table MUST be one of the valid tables
- format MUST be "json", "regex", "kv", or "csv"
- for "kv" records separated by a delimiter other than whitespace (e.g. "A|dev=1|evt=2"), add "kv_delimiter": "|" and map fields by bare key name (e.g. "HostName": "dev")
- for "regex", add "regex_pattern" with named groups and map fields by group name; the spec is rejected without it
- Every field path must use simple dotted notation (e.g. $.user.name)
- Transforms: lower, upper, strip, int, float, bool
- Only output the JSON object, no other text
"""
    findings = getattr(agent, "findings", [])
    prompt += "\n" + SYSTEM_NOTICE + ("\n" + warning_text(findings) if findings else "")
    try:
        resp = agent.ai_chat(
            [{"role": "user", "content": prompt}],
            json_mode=True, max_tokens=2000)
        spec = resp.json()
        if isinstance(spec, dict) and "target_table" in spec:
            return spec
        return None
    except Exception:
        return None


def _try_fix_llm_spec(agent: OnboardingAgent, llm_spec: dict) -> dict | None:
    """Retry with error feedback if spec validation fails."""
    try:
        fix_prompt = f"Your parser spec has validation errors: {validate_spec(llm_spec)}. Fix the JSON."
        resp = agent.ai_chat(
            [{"role": "user", "content": fix_prompt}],
            json_mode=True, max_tokens=2000)
        llm_spec2 = resp.json()
        if isinstance(llm_spec2, dict) and not validate_spec(llm_spec2):
            return llm_spec2
    except Exception:
        logger.warning("execute: ignored error", exc_info=True)
    return None


MERGE_KEYS = ("target_table", "time", "fields", "constants", "when", "description",
              "format", "regex_pattern", "kv_delimiter")


def _revert_if_worse(spec: dict, before: dict, samples: list[str]) -> None:
    """Keep the LLM's changes only if they parse at least as many samples as the heuristic spec did."""
    from ._onboarding_analysis import _verify_coverage
    if _verify_coverage(spec, samples)["coverage_pct"] < _verify_coverage(before, samples)["coverage_pct"]:
        spec.clear()
        spec.update(before)


def _merge_llm_spec(agent: OnboardingAgent, heuristic_spec: dict, llm_spec: dict) -> None:
    if validate_spec(llm_spec):
        llm_spec = _try_fix_llm_spec(agent, llm_spec) or llm_spec
    if isinstance(llm_spec, dict) and not validate_spec(llm_spec):
        for k in MERGE_KEYS:
            if llm_spec.get(k) and (k not in heuristic_spec or llm_spec[k]):
                heuristic_spec[k] = llm_spec[k]


def _maybe_enrich_with_llm(agent: OnboardingAgent, heuristic_spec: dict,
                           source_name: str, analysis: dict, samples: list[str]) -> None:
    """Optionally ask LLM for a better spec and merge into heuristic_spec in-place."""
    try:
        llm_spec = _llm_propose_spec(agent, source_name, analysis, samples)
        if llm_spec:
            before = copy.deepcopy(heuristic_spec)
            _merge_llm_spec(agent, heuristic_spec, llm_spec)
            _revert_if_worse(heuristic_spec, before, samples)
    except (AIDisabledError, AIBudgetExceeded):
        pass
