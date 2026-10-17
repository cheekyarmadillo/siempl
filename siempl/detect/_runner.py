"""RuleRunner (runs due rules, creates alerts) and the background scheduler thread."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime

from ..db import Database, utcnow
from ._alerts import create_alert
from ._core import _from_json, _json
from ._run_rule import run_rule_query

logger = logging.getLogger(__name__)


MAX_CONSECUTIVE_FAILURES = 5


class RuleRunner:
    """Run due rules and create alerts."""

    def __init__(self, db: Database):
        self.db = db

    def run_rule(self, rule_id: str, now: datetime | None = None) -> list[str]:
        """Execute a single rule, create alerts, return alert_ids.

        Args:
            rule_id: rule to execute
            now: override for ago()/now() in KQL queries (backfill testing)
        """
        rule = self.db.query_one("SELECT * FROM rules WHERE rule_id=?", [rule_id])
        if not rule:
            return []
        if not rule.get("enabled"):
            return []

        threshold = int(rule.get("threshold", 1))

        try:
            res = run_rule_query(self.db, rule["query"], rule_id=rule_id, now=now,
                                 query_lang=rule.get("query_lang") or "kql",
                                 lookback_minutes=rule.get("lookback_minutes") or 5)
        except Exception as e:
            self._record_failure(rule, str(e))
            return []

        if len(res.rows) < threshold:
            self._record_success(rule, len(res.rows))
            return []

        alert_ids = []
        alert_id = create_alert(self.db, rule, res.rows, res.columns)
        if alert_id:
            alert_ids.append(alert_id)
        self._record_success(rule, len(res.rows))

        return alert_ids

    def run_due(self) -> dict:
        """Run all rules that are due.  Returns summary."""
        now = utcnow()
        # Find enabled rules whose last_run_at + frequency_minutes < now
        rows = self.db.query(
            "SELECT * FROM rules WHERE enabled = TRUE "
            "AND (last_run_at IS NULL OR "
            "     last_run_at + INTERVAL (frequency_minutes) MINUTE <= ?) "
            "AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY last_run_at ASC NULLS FIRST",
            [now, now])
        total_alerts = 0
        alerts_by_rule: dict[str, int] = {}
        errors: list[str] = []

        for rule in rows:
            try:
                alert_ids = self.run_rule(rule["rule_id"])
                if alert_ids:
                    total_alerts += len(alert_ids)
                    alerts_by_rule[rule["rule_id"]] = len(alert_ids)
            except Exception as e:
                errors.append(f"{rule['rule_id']}: {e}")

        return {
            "rules_checked": len(rows),
            "alerts_generated": total_alerts,
            "alerts_by_rule": alerts_by_rule,
            "errors": errors,
        }

    def _record_success(self, rule: dict, row_count: int) -> None:
        now = utcnow()
        self.db.execute(
            "UPDATE rules SET last_run_at=?, last_row_count=?, last_error=NULL, updated_at=? "
            "WHERE rule_id=?",
            [now, row_count, now, rule["rule_id"]])

    def _record_failure(self, rule: dict, error: str) -> None:
        now = utcnow()
        self.db.execute(
            "UPDATE rules SET last_run_at=?, last_error=?, updated_at=? WHERE rule_id=?",
            [now, error[:2000], now, rule["rule_id"]])
        # Auto-disable after N consecutive failures
        # We check by counting errors in tuning history
        history = _from_json(rule.get("tuning_history", "[]"))
        recent_fails = sum(
            1 for h in history[-MAX_CONSECUTIVE_FAILURES:]
            if "consecutive_failure" in h.get("changes", {}))
        if recent_fails + 1 >= MAX_CONSECUTIVE_FAILURES:
            self.db.execute("UPDATE rules SET enabled=FALSE WHERE rule_id=?",
                            [rule["rule_id"]])
            # Record the auto-disable in tuning_history
            history.append({
                "ts": now.isoformat(),
                "changes": {"enabled": False, "auto_disabled": True,
                           "consecutive_failures": MAX_CONSECUTIVE_FAILURES},
            })
            self.db.execute(
                "UPDATE rules SET tuning_history=? WHERE rule_id=?",
                [_json(history), rule["rule_id"]])


def start_scheduler(db: Database) -> threading.Thread:
    """Start the rule scheduler in a daemon thread.  Returns the Thread."""
    def _loop():
        runner = RuleRunner(db)
        while True:
            try:
                runner.run_due()
            except Exception:
                logger.exception("_loop: ignored error")  # log? keep running
            time.sleep(30)

    t = threading.Thread(target=_loop, daemon=True, name="rule-scheduler")
    t.start()
    return t
