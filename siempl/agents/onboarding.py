"""OnboardingAgent – auto-detect parsers for pending sources and propose mapping specs.

Purpose: Given a source_id, examine stored raw samples (sources table + GenericEvents),
try to auto-detect a parser, and if none fits, propose a declarative MappingParser spec.
Works heuristically (always) with an optional LLM enrichment path.

Inputs:  source_id (str), samples (list[str|dict], optional)
Outputs: AgentResult with parser_name, target_table, spec (if proposed), coverage_pct

Deterministic flow:
  1. Read source metadata from sources table
  2. Collect raw samples from GenericEvents.RawEvent for this source
  3. Try siempl.ingest.parsers.auto_parse on each sample; tally detected parser hits
  4. If a parser gets >50% hit rate: recommend it
  5. If no parser fits: analyze sample structure (JSON, KV, CSV, regex-able)
     and propose a MappingParser spec via heuristics
  6. If AI is enabled: optionally send a compact digest to the LLM for a better spec
  7. Verify spec by running MappingParser over samples, report coverage_pct
  8. Write recommendation; on approval (dry_run=False + policy), persist parser
     and update sources, optionally reprocess GenericEvents rows

LLM enrichment (ai_enabled=True):
  - Send schema + sample digest + instructions → request spec JSON
  - Validate with siempl.ingest.mapping.validate_spec; retry once on errors
  - Merge LLM fields with heuristic proposal

Failure modes:
  - source_id not found → error
  - No samples available → "no_samples" status with recommendation to wait
  - All heuristics fail → "manual" recommendation
  - AI disabled → heuristic only (always produces a result)
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from ..db import Database, new_id
from ._injection_hold import record_review_only, scan_value
from ._onboarding_analysis import (
    FIELD_ALIASES,
    TABLE_HINTS,
    _add_field_example,
    _analyze_samples,
    _collect_samples,
    _detect_parser,
    _extract_regex_patterns,
    _guess_target_table,
    _parse_csv_sample,
    _parse_json_sample,
    _parse_kv_sample,
    _propose_heuristic_spec,
    _verify_coverage,
)
from ._onboarding_llm import (
    _llm_propose_spec,
    _maybe_enrich_with_llm,
    _merge_llm_spec,
    _try_fix_llm_spec,
)
from ._safety import findings_for_output
from .base import Agent, AgentResult

logger = logging.getLogger(__name__)


MIN_AUTO_APPLY_COVERAGE = 50.0  # a mapping parser that parses fewer samples than this is never auto-applied


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# Names below are re-exported for importers of siempl.agents.onboarding (tests, registry).
__all__ = [
    "FIELD_ALIASES", "TABLE_HINTS", "OnboardingAgent",
    "_add_field_example", "_analyze_samples", "_collect_samples", "_detect_parser",
    "_extract_regex_patterns", "_guess_target_table", "_llm_propose_spec",
    "_maybe_enrich_with_llm", "_merge_llm_spec", "_parse_csv_sample", "_parse_json_sample",
    "_parse_kv_sample", "_propose_heuristic_spec", "_try_fix_llm_spec", "_verify_coverage",
]


def _read_source_or_fail(db: Database, source_id: str) -> tuple[dict | None, AgentResult | None]:
    """Read source and return (src, error_result) if any guard triggers."""
    src = db.query_one("SELECT * FROM sources WHERE source_id=?", [source_id])
    if not src:
        return None, AgentResult(status="error", summary=f"source {source_id} not found")
    if src.get("parser") and src.get("status") == "active":
        result = AgentResult()
        result.output = {
            "source_id": source_id, "status": "already_onboarded",
            "parser": src["parser"], "target_table": src.get("target_table"),
        }
        result.summary = f"Source {source_id} already onboarded with parser {src['parser']}"
        return None, result
    return src, None


def _build_parser_detected_result(agent: OnboardingAgent, source_id: str,
                                  detected: dict, raw_samples: list[str],
                                  dry_run: bool) -> AgentResult:
    parser_name = detected["parser"]
    target_table = detected["table"] or "GenericEvents"
    hit_pct = (detected["hits"] / max(detected["total"], 1)) * 100

    rid = agent.recommend(
        kind="onboard_source",
        target=source_id,
        title=f"Use built-in parser '{parser_name}' for {source_id}",
        rationale=f"Auto-detection found parser '{parser_name}' matches {detected['hits']}/{detected['total']} "
                  f"samples ({hit_pct:.0f}%). Target table: {target_table}.",
        payload={"parser": parser_name, "target_table": target_table, "hit_pct": hit_pct,
                 "all_hits": detected["all_hits"]})

    result = AgentResult()
    result.output = {
        "source_id": source_id, "parser": parser_name, "target_table": target_table,
        "hit_pct": hit_pct, "total_samples": len(raw_samples),
        "recommendation_id": rid, "status": "parser_detected",
    }
    if not dry_run:
        agent._apply_onboarding(source_id, parser_name, target_table, result)
    result.summary = (f"Detected parser '{parser_name}' for {source_id} "
                      f"({hit_pct:.0f}% match). Recommendation: {rid}")
    return result


def _build_spec_proposed_result(agent: OnboardingAgent, source_id: str,
                                detected: dict, raw_samples: list[str],
                                analysis: dict, dry_run: bool) -> AgentResult:
    heuristic_spec = _propose_heuristic_spec(source_id, analysis)
    _maybe_enrich_with_llm(agent, heuristic_spec, source_id, analysis, raw_samples)
    coverage = _verify_coverage(heuristic_spec, raw_samples)
    heuristic_spec["name"] = f"mapping_{new_id('p_')[:8]}"
    hit_pct = (detected["hits"] / max(detected["total"], 1)) * 100

    rid = agent.recommend(
        kind="onboard_source",
        target=source_id,
        title=f"Proposed mapping parser for {source_id}",
        rationale=f"No built-in parser matches {source_id} (best: {hit_pct:.0f}%). "
                  f"Proposed mapping parser with coverage {coverage['coverage_pct']}% "
                  f"({coverage['parsed']}/{coverage['total']} samples).",
        payload={"spec": heuristic_spec, "analysis": analysis, "coverage": coverage})

    result = AgentResult()
    result.output = {
        "source_id": source_id, "status": "spec_proposed",
        "parser": None, "recommendation_id": rid,
        "spec": heuristic_spec, "coverage": coverage,
        "detection": {"best_parser": detected["parser"], "hit_pct": hit_pct},
        "total_samples": len(raw_samples),
    }
    too_low = coverage["coverage_pct"] < MIN_AUTO_APPLY_COVERAGE
    if not dry_run and not too_low:
        agent._apply_onboarding(source_id, heuristic_spec["name"],
                                heuristic_spec["target_table"], result,
                                spec=heuristic_spec)
    result.output.update(applied=not dry_run and not too_low, needs_human=too_low)
    result.summary = (f"No built-in parser fits {source_id}. Proposed mapping parser "
                      f"'{heuristic_spec['name']}' for table {heuristic_spec['target_table']} "
                      f"({coverage['coverage_pct']}% coverage). Rec: {rid}"
                      + (f" Coverage is below {MIN_AUTO_APPLY_COVERAGE:.0f}%, so it was NOT applied; needs a human."
                         if too_low else ""))
    return result


class OnboardingAgent(Agent):
    """Auto-detect parsers for pending sources and propose mapping specs."""

    name = "onboarding"

    def execute(self, source_id: str = "", samples: list | None = None, **kw) -> AgentResult:
        if not source_id:
            return AgentResult(status="error", summary="source_id is required")

        src, err_result = _read_source_or_fail(self.db, source_id)
        if err_result is not None:
            return err_result

        raw_samples = _collect_samples(self.db, source_id, samples)
        if not raw_samples:
            result = AgentResult()
            result.summary = f"No raw samples found for source {source_id}. Source may not have ingested data yet."
            result.output = {"source_id": source_id, "status": "no_samples",
                             "recommendation": "Wait for data ingestion before onboarding."}
            return result

        self.findings = scan_value(raw_samples)  # before parser detection and the LLM see samples
        detected = _detect_parser(raw_samples, source_id)
        hit_pct = (detected["hits"] / max(detected["total"], 1)) * 100
        # Injection-looking samples: no automatic parser apply, recommendation only.
        dry_run = kw.get("dry_run", self.dry_run) or bool(self.findings)
        if self.findings:
            record_review_only(self, source_id, self.findings)

        if detected["parser"] and hit_pct > 30:
            res = _build_parser_detected_result(self, source_id, detected, raw_samples, dry_run)
        else:
            analysis = _analyze_samples(raw_samples)
            res = _build_spec_proposed_result(self, source_id, detected, raw_samples, analysis, dry_run)
        if self.findings:
            res.output.update(injection_detected=True, findings=findings_for_output(self.findings))
        return res

    # -- apply onboarding (persist parser + update source) -------------------------
    def _apply_onboarding(self, source_id: str, parser_name: str,
                          target_table: str, result: AgentResult,
                          spec: dict | None = None) -> None:
        """Persist parser configuration and update source."""
        # If mapping spec, store in parsers table
        if spec:
            try:
                self.db.execute(
                    "INSERT OR REPLACE INTO parsers(name, spec, target_table, origin, sample) VALUES (?,?,?,?,?)",
                    [parser_name, json.dumps(spec), target_table, "ai",
                     json.dumps(spec.get("fields", {}))])
                # Register the mapping parser at runtime
                try:
                    from ..ingest.mapping import _register_mapping
                    _register_mapping(spec)
                except Exception:
                    logger.warning("_apply_onboarding: ignored error", exc_info=True)
            except Exception as e:
                result.output["apply_error"] = str(e)
                return

        # Update source
        self.db.execute(
            "UPDATE sources SET parser=?, target_table=?, status='active' WHERE source_id=?",
            [parser_name, target_table, source_id])

        self.record_action(result, "onboard_source",
                           source_id=source_id, parser=parser_name,
                           target_table=target_table)

        # Reprocess GenericEvents for this source if any exist
        try:
            rows = self.db.query(
                'SELECT "RawEvent" FROM "GenericEvents" WHERE "SourceId"=? AND "SourceType" IN (?,?) LIMIT 1000',
                [source_id, "unknown", "generic_json"])
            if rows:
                self.record_action(result, "reprocess_raw_events",
                                   source_id=source_id, count=len(rows),
                                   note="GenericEvents rows found; reprocessing requires ingest pipeline call.")
        except Exception:
            logger.warning("_apply_onboarding: ignored error", exc_info=True)
