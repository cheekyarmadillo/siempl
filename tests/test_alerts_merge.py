"""Alert/incident merge: migration, status model, alert_number."""
from __future__ import annotations

import pytest

from siempl.alerts_status import InvalidSeverity, InvalidStatus, normalize_legacy, set_severity, set_status
from siempl.db import Database
from siempl.detect import create_alert
from siempl.migrations_alerts import migrate_alerts


@pytest.fixture()
def db(tmp_path):
    return Database(tmp_path / "t.duckdb")


def _rule(i):
    return {"rule_id": f"r{i}", "name": f"R{i}", "severity": "high", "frequency_minutes": 5,
            "lookback_minutes": 5, "tables": [], "entity_mappings": [{"entity_type": "ip", "column": "S"}]}


def _mk(db, i):
    return create_alert(db, _rule(i), rows=[[f"10.0.0.{i}"]], columns=["S"])


def test_legacy_mapping():
    assert normalize_legacy("closed", "true_positive") == "closed_tp"
    assert normalize_legacy("closed", "benign") == "closed_fp"
    assert normalize_legacy("closed", None) == "closed_fp"
    assert normalize_legacy("triaging", None) == "active"
    assert normalize_legacy("escalated", None) == "active"
    assert normalize_legacy(None, None) == "new"
    assert normalize_legacy("active", None) == "active"


def test_alert_numbers_unique_monotonic(db):
    ids = [_mk(db, i) for i in range(20)]
    nums = [db.query_one("SELECT alert_number n FROM alerts WHERE alert_id=?", [a])["n"] for a in ids]
    assert nums == sorted(nums) and len(set(nums)) == 20 and nums[0] == 1


def test_migration_backfill_and_idempotent(db):
    for i, st, v in [(1, "closed", "true_positive"), (2, "escalated", None), (3, "triaging", None), (4, "closed", "false_positive")]:
        db.execute("INSERT INTO alerts(alert_id,rule_id,title,severity,status,verdict,created_at) "
                   "VALUES (?,?,?,?,?,?, now() + to_seconds(?))", [f"old{i}", "r", "t", "low", st, v, i])
    db.execute("INSERT INTO incidents(incident_id,title,owner,summary) VALUES ('inc1','T','bob','S')")
    db.execute("UPDATE alerts SET incident_id='inc1' WHERE alert_id='old1'")
    db.execute("UPDATE alerts SET alert_number=NULL")
    db.set_setting("alerts_merged_v1", False)
    migrate_alerts(db)
    snap = db.query("SELECT alert_id,alert_number,status,owner FROM alerts ORDER BY alert_number")
    assert [r["alert_number"] for r in snap] == [1, 2, 3, 4]
    assert [r["status"] for r in snap] == ["closed_tp", "active", "active", "closed_fp"]
    assert snap[0]["owner"] == "bob"
    ncom = db.query_one("SELECT count(*) c FROM alert_comments WHERE alert_id='old1'")["c"]
    assert ncom >= 1
    migrate_alerts(db)
    assert db.query("SELECT alert_id,alert_number,status,owner FROM alerts ORDER BY alert_number") == snap
    assert db.query_one("SELECT count(*) c FROM alert_comments WHERE alert_id='old1'")["c"] == ncom
    assert db.query_one("SELECT nextval('alert_number_seq') n")["n"] == 5


def test_set_status_reputation_once(db):
    aid = _mk(db, 7)
    assert set_status(db, aid, "closed_tp", "user:t")
    rep = db.query_one("SELECT tp_count c, reputation r FROM entities WHERE entity_id='ip:10.0.0.7'")
    assert rep["c"] == 1
    set_status(db, aid, "active", "user:t")
    set_status(db, aid, "closed_tp", "user:t")
    rep2 = db.query_one("SELECT tp_count c, reputation r FROM entities WHERE entity_id='ip:10.0.0.7'")
    assert rep2 == rep
    assert db.query_one("SELECT status s, verdict v FROM alerts WHERE alert_id=?", [aid]) == {"s": "closed_tp", "v": "true_positive"}


def test_set_status_and_severity_validation(db):
    aid = _mk(db, 9)
    with pytest.raises(InvalidStatus):
        set_status(db, aid, "closed", "user:t")
    with pytest.raises(InvalidSeverity):
        set_severity(db, aid, "urgent", "user:t")
    assert set_severity(db, aid, "critical", "user:t")
    assert db.query_one("SELECT severity s FROM alerts WHERE alert_id=?", [aid])["s"] == "critical"
    assert set_status(db, "nope", "active", "user:t") is False
