"""Agent scheduler: runs recurring agent tasks on a configurable interval.

Safety:
  - Gated by settings['agent_schedule_enabled'] (default False)
  - Respects agent policy mode 'off'
  - Never raises (all errors caught and logged)
  - Runs in a daemon thread

Schedule (configurable via settings):
  - tuning agent: every `agent_tuning_interval_minutes` (default 360 = 6h)
  - optimizer agent: every `agent_optimizer_interval_minutes` (default 1440 = 24h)
  - triage new alerts: every `agent_triage_interval_minutes` (default 5)
  - retention purge: every `agent_retention_interval_minutes` (default 1440 = 24h)
  - rule expiry: every `agent_rule_expiry_interval_minutes` (default 60)
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import UTC, datetime

from ..db import Database
from .registry import run_agent

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _safe_log(db: Database, agent_name: str, message: str) -> None:
    """Log a scheduler message to agent_runs without raising."""
    try:
        from ..db import new_id
        db.execute(
            "INSERT INTO agent_runs(run_id,agent,status,dry_run,summary) VALUES (?,?,?,?,?)",
            [new_id("sch_"), f"scheduler:{agent_name}", "ok", True, message])
    except Exception:
        logger.debug("_safe_log: ignored error", exc_info=True)


def start_agent_scheduler(db: Database) -> threading.Thread | None:
    """Start the agent scheduler daemon thread.

    Returns the thread if started, None if scheduling is disabled.

    Settings used:
      agent_schedule_enabled (default False)
      agent_tuning_interval_minutes (default 360)
      agent_optimizer_interval_minutes (default 1440)
      agent_triage_interval_minutes (default 5)
      agent_retention_interval_minutes (default 1440)
      agent_rule_expiry_interval_minutes (default 60)
    """
    if not db.get_setting("agent_schedule_enabled", False):
        return None

    intervals = {
        "tuning": int(db.get_setting("agent_tuning_interval_minutes", 360)),
        "optimizer": int(db.get_setting("agent_optimizer_interval_minutes", 1440)),
        "triage": int(db.get_setting("agent_triage_interval_minutes", 5)),
        "retention": int(db.get_setting("agent_retention_interval_minutes", 1440)),
        "rule_expiry": int(db.get_setting("agent_rule_expiry_interval_minutes", 60)),
    }

    def _loop() -> None:
        last_run: dict[str, datetime] = {}

        while True:
            try:
                now = _utcnow()

                # Triage new alerts
                triage_interval = intervals["triage"]
                if triage_interval > 0:
                    last = last_run.get("triage")
                    if last is None or (now - last).total_seconds() >= triage_interval * 60:
                        last_run["triage"] = now
                        try:
                            from .triage import triage_new_alerts
                            triage_new_alerts(db, limit=20)
                        except Exception as e:
                            _safe_log(db, "triage_scheduler", f"Error: {e}")

                # Tuning agent (daily by default)
                tuning_interval = intervals["tuning"]
                if tuning_interval > 0:
                    last = last_run.get("tuning")
                    if last is None or (now - last).total_seconds() >= tuning_interval * 60:
                        last_run["tuning"] = now
                        try:
                            run_agent(db, "tuning")
                        except Exception as e:
                            _safe_log(db, "tuning_scheduler", f"Error: {e}")

                # Optimizer agent (daily by default)
                opt_interval = intervals["optimizer"]
                if opt_interval > 0:
                    last = last_run.get("optimizer")
                    if last is None or (now - last).total_seconds() >= opt_interval * 60:
                        last_run["optimizer"] = now
                        try:
                            run_agent(db, "optimizer")
                        except Exception as e:
                            _safe_log(db, "optimizer_scheduler", f"Error: {e}")

                # Retention purge (daily by default)
                ret_interval = intervals["retention"]
                if ret_interval > 0:
                    last = last_run.get("retention")
                    if last is None or (now - last).total_seconds() >= ret_interval * 60:
                        last_run["retention"] = now
                        try:
                            from ..agents.optimizer import purge_expired
                            result = purge_expired(db)
                            _safe_log(db, "retention", f"Purged {result['total_deleted']} rows from {len(result['tables'])} tables")
                        except Exception as e:
                            _safe_log(db, "retention", f"Error: {e}")

                # Rule expiry
                exp_interval = intervals["rule_expiry"]
                if exp_interval > 0:
                    last = last_run.get("rule_expiry")
                    if last is None or (now - last).total_seconds() >= exp_interval * 60:
                        last_run["rule_expiry"] = now
                        try:
                            db.execute(
                                "UPDATE rules SET enabled=FALSE WHERE expires_at IS NOT NULL AND expires_at < ? AND enabled=TRUE",
                                [now])
                        except Exception as e:
                            _safe_log(db, "rule_expiry", f"Error: {e}")

            except Exception:
                logger.debug("_loop: ignored error", exc_info=True)  # outer safety net

            # Sleep 30 seconds between loop iterations
            time.sleep(30)

    thread = threading.Thread(target=_loop, daemon=True, name="agent_scheduler")
    thread.start()
    return thread
