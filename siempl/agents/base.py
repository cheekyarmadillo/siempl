"""Agent base class + policy resolution. Every agent subclasses Agent.

Rules every agent MUST follow:
  1. Work deterministically first (heuristics/SQL). Use `self.llm` only to enrich, inside try/except
     AIDisabledError/AIBudgetExceeded -> fall back to the deterministic result. With ai_enabled=False
     (the default) every agent must still run end-to-end and produce a useful non-AI result or a
     clear 'ai disabled' note.
  2. Side effects (closing alerts, enabling rules, creating filters, remediation) happen only via
     `self.act(...)`-style guarded helpers: when self.dry_run is True they are RECORDED in the run
     output, not executed. Dry-run is the default (settings['agents_dry_run']).
  3. Recommendations that need a human go to the `recommendations` table.
  4. Everything is logged in `agent_runs`.
"""
from __future__ import annotations

import json
import traceback
from dataclasses import dataclass, field

from ..ai.llm import AIBudgetExceeded, AIDisabledError, LLMClient
from ..audit import record as audit_record
from ..db import Database, new_id, utcnow

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]
MODES = ["off", "monitor", "recommend", "auto_close", "auto_remediate"]


@dataclass
class Policy:
    mode: str = "recommend"
    can_close: bool = True
    can_escalate: bool = True
    can_remediate: bool = False
    can_create_temp_rules: bool = True


def resolve_policy(db: Database, agent: str, *, severity: str | None = None, rule_id: str | None = None) -> Policy:
    """Most specific wins: rule > severity > global."""
    for scope, val in (("rule", rule_id), ("severity", severity), ("global", "*")):
        if val is None:
            continue
        r = db.query_one("SELECT * FROM agent_policy WHERE agent=? AND scope=? AND scope_value=?", [agent, scope, val])
        if r:
            return Policy(r["mode"], r["can_close"], r["can_escalate"], r["can_remediate"], r["can_create_temp_rules"])
    return Policy()


@dataclass
class AgentResult:
    status: str = "ok"                       # ok | skipped | error
    summary: str = ""
    output: dict = field(default_factory=dict)
    actions: list[dict] = field(default_factory=list)   # intended/performed side effects


class Agent:
    name = "agent"

    def __init__(self, db: Database, llm: LLMClient | None = None, dry_run: bool | None = None):
        self.db = db
        self.llm = llm or LLMClient(db)
        self.dry_run = bool(db.get_setting("agents_dry_run", True)) if dry_run is None else dry_run
        self.tokens_in = self.tokens_out = 0
        self.cost = 0.0

    # -- subclasses implement ---------------------------------------------------------
    def execute(self, **kw) -> AgentResult:
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------------------
    def ai_chat(self, messages, **kw):
        """Wrapper that accounts tokens to this run. Raises AIDisabledError when AI is off.
        Respects per-agent model override (agent_model_<name> setting)."""
        model = kw.pop("model", None)
        if model is None:
            override = self.db.get_setting(f"agent_model_{self.name}", "")
            model = override if override else None
        r = self.llm.chat(messages, agent=self.name, model=model, **kw)
        self.tokens_in += r.tokens_in; self.tokens_out += r.tokens_out; self.cost += r.cost_usd
        return r

    def record_action(self, result: AgentResult, action: str, **detail) -> None:
        result.actions.append({"action": action, "executed": not self.dry_run, **detail})

    def recommend(self, kind: str, target: str, title: str, rationale: str, payload: dict | None = None,
                  est_savings: str | None = None) -> str:
        rid = new_id("rec_")
        self.db.execute(
            "INSERT INTO recommendations(rec_id,agent,kind,target,title,rationale,payload,est_savings) VALUES (?,?,?,?,?,?,?,?)",
            [rid, self.name, kind, target, title, rationale, json.dumps(payload or {}), est_savings])
        return rid

    def run(self, input_ref: str = "", **kw) -> AgentResult:
        run_id = new_id("run_")
        self.db.execute("INSERT INTO agent_runs(run_id,agent,status,dry_run,input_ref) VALUES (?,?,?,?,?)",
                        [run_id, self.name, "running", self.dry_run, input_ref])
        try:
            res = self.execute(**kw)
            res.output.setdefault("actions", res.actions)
        except (AIDisabledError, AIBudgetExceeded) as e:
            res = AgentResult(status="skipped", summary=f"AI unavailable: {e}")
        except Exception as e:  # noqa: BLE001
            res = AgentResult(status="error", summary=str(e), output={"trace": traceback.format_exc()[-2000:]})
        self.db.execute(
            "UPDATE agent_runs SET finished_at=?, status=?, summary=?, output=?, error=?, tokens_in=?, tokens_out=?, cost_usd=? WHERE run_id=?",
            [utcnow(), res.status, res.summary, json.dumps(res.output, default=str),
             res.summary if res.status == "error" else None, self.tokens_in, self.tokens_out, self.cost, run_id])
        # Audit log every agent run / action
        for act in res.actions:
            audit_record(self.db, f"agent:{self.name}", act.get("action", "unknown"),
                         act.get("target_type", "agent"), act.get("target_id", input_ref or ""),
                         outcome="ok" if act.get("executed") else "dry_run",
                         details={"run_id": run_id, "dry_run": self.dry_run, **{k: v for k, v in act.items() if k not in ("action", "executed", "target_type", "target_id")}})
        res.output["run_id"] = run_id
        return res
