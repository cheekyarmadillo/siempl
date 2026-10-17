"""Runtime configuration and defaults. Single source of truth for paths and setting defaults.

Paths honor SIEMPL_HOME (tests set this to a tmp dir). Default: <repo>/data (gitignored).
SAFETY: ai_enabled defaults to False. Nothing in this codebase may call an LLM unless
settings['ai_enabled'] is true AND a key is available (see siempl/ai/llm.py).
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def home() -> Path:
    p = Path(os.environ.get("SIEMPL_HOME", REPO_ROOT / "data"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_path() -> Path:
    return home() / "siempl.duckdb"


# Defaults for the key/value `settings` table. get_setting() falls back to these.
DEFAULT_SETTINGS: dict = {
    # ---- AI master switch & budget (all agents funnel through siempl/ai/llm.py) ----
    "ai_enabled": False,                      # MASTER KILL SWITCH. Off until the operator enables it.
    "ai_daily_usd_cap": 1.00,                 # hard stop per UTC day, estimated from usage
    "ai_daily_token_cap": 500_000,            # hard stop per UTC day (in+out)
    "ai_total_usd_budget": 10.0,              # lifetime budget cap (USD)
    "ai_default_model": "openai/gpt-5.6-sol",     # OpenRouter model id
    "ai_cheap_model": "google/gemini-3.8-flash",         # used by the log-alert agent
    "ai_price_in_per_mtok": 1.0,              # fallback USD/Mtok when OpenRouter omits cost
    "ai_price_out_per_mtok": 4.0,
    "openrouter_key_file": "~/.config/siempl/openrouter.key",   # or env OPENROUTER_API_KEY
    # ---- agents ----
    "agents_dry_run": True,                   # dry-run = record intended actions, change nothing
    "remediation_enabled": False,             # even when True, remediation connectors are stubs
    "log_alert_agent_enabled": False,         # optional per-line LLM agent; off by default
    "log_alert_agent_sample_rate": 0.0,
    # ---- server ----
    "bind_host": "127.0.0.1",
    "bind_port": 8765,
    "syslog_udp_port": 5514,                  # unprivileged default; map 514->5514 if needed
    "syslog_tcp_port": 5514,
    "rule_scheduler_enabled": True,
    "default_retention_days": 30,
    # ---- agent scheduler ----
    "agent_schedule_enabled": False,             # master switch: recurring agent runs
    "agent_tuning_interval_minutes": 360,        # tuning agent runs every 6h
    "agent_optimizer_interval_minutes": 1440,    # optimizer runs daily
    "agent_triage_interval_minutes": 5,          # triage_new_alerts every 5 min
    "agent_retention_interval_minutes": 1440,    # retention purge daily
    "agent_rule_expiry_interval_minutes": 60,    # rule expiry check hourly
    # ---- optimizer ----
    "optimizer_high_volume_threshold": 10000,    # rows/day above which to recommend filters
}
