"""End-to-end: builtin SSH rules fire on REAL sshd syslog lines.

Regression for the 2026-10-12 root-cause fix: round 1 worked around the fact
that real sshd lines ("Failed password for invalid user admin from ...")
parsed to AuthEvents with AuthMethod='password' and no TargetUserName, so
builtin rules 1-3 (filter AuthMethod == "ssh", group by TargetUserName) could
never fire on real data. The parser now emits AuthMethod='ssh',
TargetUserName=<account>, LogonType=<password|publickey|...>.

Feeds ~20 realistic raw sshd syslog lines (RFC3164 + RFC5424) from one
attacker IP through the real IngestPipeline, installs builtin rules, and
asserts rules 1 (brute force), 2 (success after failures) and 3 (password
spray — same root cause) all fire.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta

import pytest

from siempl.db import Database
from siempl.detect import RuleRunner
from siempl.detect.builtin import install_builtin_rules
from siempl.ingest import IngestPipeline

ATTACKER = "203.0.113.77"
HOST = "web01"


def _ts3164(ts: datetime) -> str:
    return ts.strftime("%b %d %H:%M:%S")


def _ts5424(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_attack_lines() -> list[str]:
    """~25 realistic sshd lines: brute force of root (>=10 fails), spray across
    10 other accounts, then a successful root login. Mixed RFC3164/RFC5424,
    including 'Invalid user' and 'invalid user' variants and publickey/ki."""
    lines: list[str] = []
    base = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=9)
    pid = 32100

    def emit(i: int, msg: str, pri3164: str = "<34>", pri5424: str = "<38>"):
        ts = base + timedelta(seconds=20 * i)
        if i % 2 == 0:
            lines.append(f"{pri3164}{_ts3164(ts)} {HOST} sshd[{pid + i}]: {msg}")
        else:
            lines.append(f"{pri5424}1 {_ts5424(ts)} {HOST} sshd {pid + i} - - {msg}")

    i = 0
    # 12 failed root attempts (rule 1 needs fail_count >= 10 per SrcIp+user)
    for n in range(12):
        port = 52000 + n
        if n % 3 == 0:
            emit(i, f"Failed password for invalid user root from {ATTACKER} port {port} ssh2")
        elif n % 3 == 1:
            emit(i, f"Invalid user root from {ATTACKER} port {port}")
        else:
            emit(i, f"Failed password for root from {ATTACKER} port {port} ssh2")
        i += 1
    # Password spray: one failure each for 10 other accounts (rule 3)
    for user in ["admin", "oracle", "test", "guest", "user", "postgres",
                 "mysql", "ubuntu", "deploy", "git"]:
        emit(i, f"Failed password for invalid user {user} from {ATTACKER} port {53000 + i} ssh2")
        i += 1
    # The attacker gets in (rule 2 needs >=6 events with both failure+success)
    emit(i, f"Accepted password for root from {ATTACKER} port 54001 ssh2", "<13>", "<13>")
    i += 1
    # Normal background noise from other IPs / other methods
    emit(i, "Accepted publickey for alice from 10.0.1.50 port 54567 ssh2", "<13>", "<13>")
    i += 1
    emit(i, "Failed keyboard-interactive/pam for bob from 10.0.1.51 port 54568 ssh2")
    i += 1
    return lines


@pytest.fixture(scope="module")
def real_sshd_db():
    td = tempfile.mkdtemp(prefix="siempl_sshd_real_")
    db = Database(os.path.join(td, "test.duckdb"))
    try:
        lines = _build_attack_lines()
        pipe = IngestPipeline(db)
        result = pipe.ingest("sshd-real", lines)   # auto-detect per record
        assert result.failed == 0
        install_builtin_rules(db)
        db._siempl_test_lines = lines  # for inspection in tests
        yield db
    finally:
        db.close()
        shutil.rmtree(td, ignore_errors=True)


def _run_rule(db, name_pattern: str) -> list[str]:
    runner = RuleRunner(db)
    r = db.query_one(
        f"SELECT * FROM rules WHERE name LIKE '%{name_pattern}%' AND origin='builtin'")
    assert r, f"Rule matching '{name_pattern}' not installed"
    return runner.run_rule(r["rule_id"])


# ── parser contract on real lines ────────────────────────────────────────────

def test_real_lines_land_in_authevents_with_rule_contract(real_sshd_db):
    db = real_sshd_db
    rows = db.query('SELECT * FROM "AuthEvents" WHERE SourceId=?', ["sshd-real"])
    assert len(rows) == len(db._siempl_test_lines), (
        f"every sshd auth line should produce an AuthEvents row, got {len(rows)}")
    for r in rows:
        assert r["AuthMethod"] == "ssh", f"AuthMethod contract broken: {dict(r)}"
        assert r["TargetUserName"], f"TargetUserName must be populated: {dict(r)}"
        assert r["EventAction"] == "login"
    results = {r["EventResult"] for r in rows}
    assert results == {"success", "failure"}
    methods = {r["LogonType"] for r in rows if r["LogonType"]}
    assert "password" in methods and "publickey" in methods
    attacker_rows = [r for r in rows if r["SrcIp"] == ATTACKER]
    assert len(attacker_rows) == 23  # 12 root fails + 10 spray fails + 1 success


def test_invalid_user_lines_are_failures(real_sshd_db):
    db = real_sshd_db
    rows = db.query(
        'SELECT * FROM "AuthEvents" WHERE SourceId=? AND EventResult=?',
        ["sshd-real", "failure"])
    reasons = [r["FailureReason"] or "" for r in rows]
    assert any("Invalid user" in x for x in reasons)


# ── end-to-end: builtin rules fire on the real data ─────────────────────────

def test_rule1_brute_force_failed_logins_fires(real_sshd_db):
    alerts = _run_rule(real_sshd_db, "Repeated Failed Logins")
    assert len(alerts) >= 1, "SSH brute force (rule 1) should fire on real sshd lines"


def test_rule2_success_after_failures_fires(real_sshd_db):
    alerts = _run_rule(real_sshd_db, "Success After Failures")
    assert len(alerts) >= 1, "SSH success-after-failures (rule 2) should fire on real sshd lines"


def test_rule3_password_spray_fires(real_sshd_db):
    """Rule 3 was broken by the same root cause (no TargetUserName)."""
    alerts = _run_rule(real_sshd_db, "Password Spray")
    assert len(alerts) >= 1, "Password spray (rule 3) should fire on real sshd lines"
