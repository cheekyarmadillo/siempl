"""End-to-end: builtin rules fire on the synthetic attack data.

Covers the synth-data gaps fixed 2026-10-12 (see docs/TESTDATA.md):
  - Rules 1-2 (SSH Brute Force): synth now also emits normalized AuthEvents
    rows (AuthMethod='ssh') for the brute-force scenario, not just Syslog text.
  - Rule 6 (New Local Administrator): synth now emits a
    'net localgroup administrators ... /add' ProcessEvents record.
  - Rule 8 (Horizontal Port Scan): synth port scan now uses 60 distinct ports,
    crossing the >=50 dcount(DstPort) threshold.

Style mirrors tests/test_detect_kql.py: generate synth data, time-shift it
forward by 24h so rule ago() windows match, install builtin rules, run rules.
"""
from __future__ import annotations

import os
import shutil
import tempfile

import pytest

from siempl.db import Database
from siempl.detect import RuleRunner
from siempl.detect.builtin import install_builtin_rules
from siempl.testdata.synth import generate_all


@pytest.fixture(scope="module")
def synth_db():
    td = tempfile.mkdtemp(prefix="siempl_synth_alerts_")
    db = Database(os.path.join(td, "test.duckdb"))
    try:
        generate_all(db, seed=42)
        for table in ["AuthEvents", "ProcessEvents", "NetworkEvents",
                      "WebAccess", "FileEvents", "Syslog", "GenericEvents"]:
            try:
                db.execute(
                    f'UPDATE "{table}" SET TimeGenerated = TimeGenerated + INTERVAL 24 HOUR'
                )
                db.execute(
                    f'UPDATE "{table}" SET IngestTime = IngestTime + INTERVAL 24 HOUR'
                )
            except Exception:
                pass  # table may be empty or missing cols
        install_builtin_rules(db)
        yield db
    finally:
        db.close()
        shutil.rmtree(td, ignore_errors=True)


def _run_rule(db, name_pattern: str) -> list[str]:
    """Find a builtin rule by name pattern and run it, return alert_ids."""
    runner = RuleRunner(db)
    r = db.query_one(
        f"SELECT * FROM rules WHERE name LIKE '%{name_pattern}%' AND origin='builtin'")
    assert r, f"Rule matching '{name_pattern}' not installed"
    return runner.run_rule(r["rule_id"])


def test_ssh_brute_force_failed_logins_alerts(synth_db):
    """Rule 1 — repeated SSH failures: tail burst of 12 root failures from
    45.33.32.156 crosses fail_count >= 10."""
    alerts = _run_rule(synth_db, "Repeated Failed Logins")
    assert len(alerts) >= 1, f"SSH brute force (failed logins) rule should fire; got {alerts}"


def test_ssh_brute_force_success_after_failures_alerts(synth_db):
    """Rule 2 — success after failures: 45.33.32.156 has >=6 ssh login events
    with both failure and success results."""
    alerts = _run_rule(synth_db, "Success After Failures")
    assert len(alerts) >= 1, f"SSH brute force (success after failures) rule should fire; got {alerts}"


def test_new_local_admin_alerts(synth_db):
    """Rule 6 — 'net localgroup administrators backdoor /add' process event."""
    alerts = _run_rule(synth_db, "New Local Administrator")
    assert len(alerts) >= 1, f"New local admin rule should fire; got {alerts}"


def test_port_scan_alerts(synth_db):
    """Rule 8 — 203.0.113.99 scans 60 distinct ports across 6 hosts, crossing
    ports_scanned >= 50."""
    alerts = _run_rule(synth_db, "Horizontal Port Scan")
    assert len(alerts) >= 1, f"Port scan rule should fire; got {alerts}"
