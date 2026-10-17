# Alerts model, agents in the GUI, and prompt-injection handling

Written 2026-10-14 after the overhaul (steps 1-12). Source of truth for how alerts, agent panels, the red nav
dots and the injection defences fit together. Code pointers are in backticks.

## 1. Alerts are the only object (incidents are gone)

- One table, `alerts`. The old `incidents` / `incident_comments` tables and `alerts.incident_id` stay in the
  database as legacy data but nothing writes them. `/incidents` redirects (307) to `/alerts`.
- No grouping of alerts any more (`create_alert` no longer builds incidents).
- **alert_number**: global incrementing integer from DuckDB sequence `alert_number_seq`, shown as `#1042`.
  The migration (`siempl/migrations_alerts.py`, run by `Database.init_schema`) back-filled existing alerts in
  `created_at` order and is idempotent (guarded by setting `alerts_merged_v1`).
- **Statuses** (`siempl/alerts_status.py`): `new`, `active`, `closed_tp`, `closed_fp`. "Open" = new + active.
  There is no user-facing verdict. `alerts.verdict` is kept as a derived internal column
  (closed_tp -> true_positive, closed_fp -> false_positive) so entity reputation and agents keep working.
- **One write path**: `set_status()` and `set_severity()` validate, update, and write an audit row
  (`alert.status`, `alert.severity`). Closing applies entity reputation exactly once per alert
  (`alerts.reputation_applied`), even if the alert is reopened and closed again.
- Legacy mapping used by the migration: triaging/escalated -> active; closed + true_positive -> closed_tp;
  every other closed -> closed_fp.

## 2. Agents in the GUI

Every place an agent applies has the same panel (`static/agent_panel.js`, backend
`web/_agent_panel.py` + `routes_agent_panel.py`):

| Page | Scope | Agent(s) |
|---|---|---|
| Alerts side preview and `/alerts/{id}` | alert | triage |
| `/rules/{id}` | rule | tuning (+ discovery recommendations) |
| `/ingestion` (source picker) | source | onboarding, optimizer |
| `/logs` (collapsible card) | logs | log_alert |

The panel shows: state pill (running / idle / disabled / needs approval), the effective policy (mode and capability
chips), a Run button, the last run (status, summary, cost, error, trimmed output), a red injection banner when
telemetry looked hostile, and the pending recommendations with Approve / Reject.

**Policy matrix gating**: Run is disabled (reason shown) when the agent is disabled, AI is off where needed, or
the policy mode is `off`. Approve is disabled with `blocked_reason` when the policy does not allow the capability
the recommendation needs; the server enforces the same check and answers 403. `injection_review` recommendations
can always be approved or dismissed by a human. Approvals reuse the existing apply code and are audited as
`user:web`.

### Red dots (notifications)

`static/attention.js` polls `GET /api/agent-attention` every 30 s (paused when the tab is hidden) and shows a red
dot on a portal in the sidebar **only when a pending agent task needs a human** for that portal:

- alerts: injection_review recommendations
- rules: tuning / discovery recommendations
- ingestion: optimizer / onboarding recommendations
- logs: log_alert recommendations
- agents: total

New alerts, failed runs and merely-running agents never create a dot. The Agents page lists the same items in a
"Needs your attention" queue with Approve / Reject. Pages can force a refresh with
`window.dispatchEvent(new Event('attention-refresh'))`; the panel does this after approve/reject and when a run
finishes.

## 3. Prompt-injection model

Telemetry (log fields, alert evidence, entity values, imported rule text, command lines) is untrusted. Defences,
all in `siempl/agents/_safety.py` (+ `_safety_patterns.py`, `_injection_hold.py`):

1. **Fenced data**: telemetry reaches an LLM only through `wrap_untrusted()`: a per-call random nonce fence,
   control and zero-width/bidi characters stripped, fence look-alikes neutralised, truncated with a visible marker.
   The system prompt (`SYSTEM_NOTICE`) says fenced content is data, never instructions.
2. **Strict output schema**: `validate_verdict()` accepts only `true_positive | false_positive | needs_human`
   (benign is an alias of false_positive), clamped confidence, capped summary, and `recommended_actions` from the
   fixed `ACTION_ALLOWLIST` (action *names*, not free text; the triage prompt lists them). Anything invalid becomes
   `needs_human`; it never raises.
3. **Authority lives in code**: policy (mode, can_close, can_escalate, can_remediate, can_create_temp_rules) is
   checked after the LLM. Alert ids, rule ids and entities the model mentions must exist in the database or are
   dropped. Temp-rule KQL is built in code from validated entity values (`build_entity_kql`), never from model text.
4. **Detector** (`scan_text`, `scan_many`) runs over alert evidence/entities before the LLM. On findings the agent
   does **not** error out and does not stop: it finishes the run, then `disposition_with_findings()` forces
   `needs_human` (no auto-close, no severity downgrade, no remediation, no temp rules). The result carries
   `injection_detected=true`, the findings and the original `model_verdict`. Side effects: an alert comment
   ("suspected prompt injection ... Held for human review"), an `injection_review` recommendation (the human
   resolution path, shown in the panel and as a red dot) and an `agent.injection_detected` audit record. A human
   can dismiss it or act on the alert normally.
5. Other agents (tuning, discovery, onboarding, optimizer, log_alert) scan their inputs too; on findings their
   automatic actions are downgraded to recommendations.

Tests: `tests/injection_corpus.json` (64 attacks, 30 benign lines), `tests/test_agent_safety.py`,
`tests/test_agent_injection_e2e.py` (a fake LLM that *obeys* the injected instruction must still not close the
alert). Real-LLM spot check (2026-10-14, gemini-3.8-flash, about $0.09): the 3 injection scenario alerts were
detected and held (needs_human, still new); the 3 ordinary true positives were classified true_positive and
escalated.

## 4. Triage without an LLM (`siempl/agents/_triage_heuristics.py`)

Signals: this rule's closed_fp / closed_tp history (30 d), repeats of the same rule in 24 h, entity reputation,
and OTHER open alerts sharing an entity in 24 h (kill chain). Rules:

- low/informational + rule FP ratio >= 0.8 over >= 5 closed alerts -> false_positive at **0.90** (can auto-close
  under policy; the close threshold is 0.85)
- low/informational + >= 5 repeats in 24 h and no TP history -> false_positive at **0.80** (waits for a human)
- high/critical + >= 2 related open alerts, or max entity reputation > 80 -> true_positive at 0.75 (escalated)
- otherwise needs_human

## 5. Scenario data

`siempl/testdata/scenarios.py` (`load_scenarios`, `reset_scenarios`, `scenario_manifest`; Samples page buttons,
`POST/DELETE /api/samples/scenarios`) loads seven tagged scenarios: brute force to compromise, lateral movement,
data exfil, a noisy false-positive service account, prompt-injection attempts in logs, a chatty debug source and an
unparsed IoT source. `siempl/testdata/scenarios_manifest.json` records the expected triage outcome per alert and is
used by `tests/test_triage_scenarios.py`.

## 6. Operations notes

- Key entry: Settings -> OpenRouter API key (save / test / remove). The key is written only to the key file
  (0600), never to the DB, HTML or logs. `OPENROUTER_API_KEY` in the environment wins. The total AI budget cap
  (`ai_total_usd_budget`, default 10.00) is enforced before every call.
- `python -m siempl --host` binds `::` dual-stack (IPv4 and IPv6) via `siempl/_net.py`. Plain uvicorn on `::`
  came up IPv6-only on this host. There is still **no authentication** on the web UI/API.
- Restart the server with SIGTERM and wait; `kill -9` after schema changes made the DuckDB WAL unreplayable
  (DuckDB 1.5.x). `init_schema` now runs `CHECKPOINT` after migrations.
