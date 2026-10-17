"""Settings routes — audited, validated, replaces legacy POST /api/settings.

Mounted BEFORE legacy routes.py so /api/settings and /settings override.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..audit import record as audit_record
from ..db import Database

# Import helpers from routes.py (same template env)
from ._settings_key import public_status
from .routes import _ctx, _severity_choices, templates  # type:ignore[attr-defined]

logger = logging.getLogger(__name__)

# Feature-detect agent modules
_AGENTS_BASE = None
_MODES = ["off", "monitor", "recommend", "auto_close", "auto_remediate"]
try:
    from siempl.agents.base import MODES as _MODES_IMPORTED  # type:ignore[import-untyped]
    _AGENTS_BASE = True
    _MODES = list(_MODES_IMPORTED)
except ImportError:
    _AGENTS_BASE = False


def _key_status(db: Database) -> str:
    import os
    if os.environ.get("OPENROUTER_API_KEY"):
        return "found"
    kf = db.get_setting("openrouter_key_file", "")
    if kf:
        from pathlib import Path
        if Path(kf).expanduser().is_file():
            return "found"
    return "not found"


def _usage_data(db: Database) -> dict:
    try:
        from ..ai.llm import LLMClient
        llm = LLMClient(db)
        today = llm.usage_today()
        total = llm.usage_total()
        return {
            "today_usd": today["usd"],
            "today_tokens": today["tokens"],
            "total_usd": total["usd"],
            "total_tokens": total["tokens"],
        }
    except Exception:
        return {"today_usd": 0.0, "today_tokens": 0, "total_usd": 0.0, "total_tokens": 0}


def _model_choices(db: Database) -> list[str]:
    default = db.get_setting("ai_default_model", "")
    cheap = db.get_setting("ai_cheap_model", "")
    choices = list(dict.fromkeys([default, cheap, "google/gemini-3.8-flash",
                                   "deepseek/deepseek-v4-pro", "anthropic/claude-sonnet-4",
                                   "openai/gpt-4.1-mini"]))
    return [c for c in choices if c]


def build_router(db: Database) -> APIRouter:
    r = APIRouter()

    @r.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        policy_rows: list[dict] = []
        try:
            policy_rows = db.query("SELECT * FROM agent_policy ORDER BY agent, scope DESC, scope_value")
        except Exception:
            logger.debug("settings_page: ignored error", exc_info=True)

        usage = _usage_data(db)
        budget = float(db.get_setting("ai_total_usd_budget", 10.0))

        # Per-agent model overrides
        agent_models: dict[str, str] = {}
        try:
            from siempl.agents.registry import list_agents
            for name in list_agents():
                agent_models[name] = db.get_setting(f"agent_model_{name}", "")
        except Exception:
            logger.debug("settings_page: ignored error", exc_info=True)

        return templates.TemplateResponse(request, "settings.html", _ctx(
            request, "settings", "Settings",
            ai_enabled=db.get_setting("ai_enabled", False),
            ai_daily_usd_cap=db.get_setting("ai_daily_usd_cap", 1.0),
            ai_daily_token_cap=db.get_setting("ai_daily_token_cap", 500_000),
            ai_total_usd_budget=budget,
            ai_default_model=db.get_setting("ai_default_model", ""),
            ai_cheap_model=db.get_setting("ai_cheap_model", ""),
            agents_dry_run=db.get_setting("agents_dry_run", True),
            remediation_enabled=db.get_setting("remediation_enabled", False),
            log_alert_agent_enabled=db.get_setting("log_alert_agent_enabled", False),
            agent_schedule_enabled=db.get_setting("agent_schedule_enabled", False),
            key_status=_key_status(db),
            key_info=public_status(db),
            usage_today=usage,
            policy_rows=policy_rows,
            severity_choices=_severity_choices(db),
            all_modes=_MODES,
            agent_models=agent_models,
            model_choices=_model_choices(db),
        ), headers={"Cache-Control": "no-cache"})

    # ---- API: audited settings update ----------------------------------------

    @r.post("/api/settings")
    async def api_settings_update(request: Request):
        """Update settings. Validates types, audits every changed key. Never logs key material."""
        try:
            body = await request.json()
        except Exception as e:
            return JSONResponse({"error": f"Invalid JSON: {e}"}, status_code=400)

        # Allowed keys and their validators
        validators: dict[str, Any] = {
            "ai_enabled": bool,
            "ai_daily_usd_cap": lambda v: max(0.0, float(v)),
            "ai_daily_token_cap": lambda v: max(0, int(v)),
            "ai_total_usd_budget": lambda v: max(0.0, float(v)),
            "ai_default_model": str,
            "ai_cheap_model": str,
            "agents_dry_run": bool,
            "remediation_enabled": bool,
            "log_alert_agent_enabled": bool,
            "agent_schedule_enabled": bool,
        }

        changed: list[dict] = []
        errors: list[str] = []

        for k, v in body.items():
            if k in validators:
                try:
                    old = db.get_setting(k, None)
                    coerced = validators[k](v)
                    db.set_setting(k, coerced)
                    changed.append({"key": k, "old": old, "new": coerced})
                except (ValueError, TypeError) as e:
                    errors.append(f"{k}: {e}")
            elif k.startswith("agent_model_"):
                try:
                    old = db.get_setting(k, None)
                    db.set_setting(k, str(v))
                    changed.append({"key": k, "old": old, "new": str(v)})
                except Exception as e:
                    errors.append(f"{k}: {e}")
            elif k.startswith("agent_") and k.endswith("_interval_minutes"):
                try:
                    old = db.get_setting(k, None)
                    mins = max(0, int(v))
                    db.set_setting(k, mins)
                    changed.append({"key": k, "old": old, "new": mins})
                except (ValueError, TypeError) as e:
                    errors.append(f"{k}: {e}")
            else:
                # Silently skip unknown keys (backward compat)
                pass

        # Audit every changed key (never log key material — these are setting names/values, not API keys)
        for c in changed:
            audit_record(db, "user:web", "settings.update", "setting", c["key"],
                         outcome="ok", details={"old": c["old"], "new": c["new"]})

        if errors:
            return JSONResponse({"ok": False, "errors": errors}, status_code=400)

        return {"ok": True, "changed": [c["key"] for c in changed]}

    # ---- Kill switch ---------------------------------------------------------

    @r.post("/api/settings/kill-switch")
    async def api_kill_switch(request: Request):
        """Emergency kill: disable AI and agent scheduling immediately."""
        try:
            old_ai = db.get_setting("ai_enabled", False)
            old_sched = db.get_setting("agent_schedule_enabled", False)
            db.set_setting("ai_enabled", False)
            db.set_setting("agent_schedule_enabled", False)
            audit_record(db, "user:web", "settings.kill_switch", "setting", "ai_enabled+agent_schedule_enabled",
                         outcome="ok", details={"ai_enabled": {"old": old_ai, "new": False},
                                                "agent_schedule_enabled": {"old": old_sched, "new": False}})
            return {"ok": True, "ai_enabled": False, "agent_schedule_enabled": False}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ---- Per-agent model override ---------------------------------------------

    @r.post("/api/agents/{agent_name}/model")
    async def api_agent_model(agent_name: str, request: Request):
        try:
            body = await request.json()
            model = str(body.get("model", ""))
            key = f"agent_model_{agent_name}"
            old = db.get_setting(key, None)
            db.set_setting(key, model)
            audit_record(db, "user:web", "agent.model", "setting", key,
                         outcome="ok", details={"old": old, "new": model})
            return {"ok": True, "agent": agent_name, "model": model}
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    return r
