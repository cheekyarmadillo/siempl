"""Branch and boundary tests for the deterministic triage heuristic (AI disabled)."""

import json
from datetime import UTC, datetime, timedelta

import pytest

from siempl.agents._safety import ACTION_ALLOWLIST
from siempl.agents._triage_heuristics import heuristic_verdict
from siempl.db import Database


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "h.duckdb"))


def _add(db, aid, *, rule="r1", title="Test Alert", severity="low", ents=None,
         status="new", age=timedelta(0), updated_age=None):
    created = _now() - age
    updated = _now() - (updated_age if updated_age is not None else age)
    db.execute(
        """INSERT INTO alerts(alert_id,rule_id,title,severity,status,entities,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        [aid, rule, title, severity, status,
         json.dumps(ents or [{"type": "ip", "value": f"10.9.{len(aid)}.{len(aid)}"}]),
         created, updated])
    return db.query_one("SELECT * FROM alerts WHERE alert_id=?", [aid])


def _ip(value, rep=50, fp=0, tp=0):
    return {"entity_id": f"ip:{value}", "type": "ip", "value": value,
            "reputation": rep, "fp_count": fp, "tp_count": tp}


def _verdict(db, alert, entities=None, rule=None):
    ents = entities if entities is not None else [_ip("10.0.0.1")]
    v = heuristic_verdict(db, alert, rule, ents)
    assert v["source"] == "heuristic"
    assert set(v) >= {"verdict", "confidence", "severity_adjustment", "summary",
                      "evidence_refs", "recommended_actions", "monitor_entities",
                      "monitor_patterns", "source"}
    assert all(a in ACTION_ALLOWLIST for a in v["recommended_actions"])
    return v


def _closed(db, rule, n_fp, n_tp=0, prefix="h"):
    for i in range(n_fp):
        _add(db, f"{prefix}fp{i}", rule=rule, status="closed_fp", age=timedelta(days=2))
    for i in range(n_tp):
        _add(db, f"{prefix}tp{i}", rule=rule, status="closed_tp", age=timedelta(days=2))


# ---- (a) rule history: FP ratio ------------------------------------------------

def test_rule_fp_ratio_five_closed_is_false_positive(db):
    _closed(db, "r1", 5)
    alert = _add(db, "cur")
    v = _verdict(db, alert)
    assert v["verdict"] == "false_positive"
    assert v["confidence"] == 0.90
    assert "close_alert" in v["recommended_actions"]


def test_rule_fp_ratio_exactly_080_is_false_positive(db):
    _closed(db, "r1", 4, n_tp=1)
    alert = _add(db, "cur")
    assert _verdict(db, alert)["verdict"] == "false_positive"


def test_rule_fp_ratio_079_is_needs_human(db):
    _closed(db, "r1", 79, n_tp=21)
    alert = _add(db, "cur")
    v = _verdict(db, alert)
    assert v["verdict"] == "needs_human"
    assert v["confidence"] == 0.50


def test_rule_fp_ratio_needs_at_least_five_closed(db):
    _closed(db, "r1", 4)
    alert = _add(db, "cur")
    assert _verdict(db, alert)["verdict"] == "needs_human"


def test_rule_history_older_than_30_days_is_ignored(db):
    for i in range(6):
        _add(db, f"old{i}", rule="r1", status="closed_fp", age=timedelta(days=40))
    alert = _add(db, "cur")
    assert _verdict(db, alert)["verdict"] == "needs_human"


def test_high_severity_never_uses_rule_fp_rule(db):
    _closed(db, "r1", 6)
    alert = _add(db, "cur", severity="high")
    assert _verdict(db, alert)["verdict"] == "needs_human"


# ---- (b) repetition in 24h ----------------------------------------------------

def _repeats(db, n, *, rule="r1", title="Test Alert", ents=None, age=timedelta(hours=1)):
    for i in range(n):
        _add(db, f"rep{rule}{title[:3]}{i}{len(ents or [])}", rule=rule, title=title,
             ents=ents, age=age)


def test_four_repeats_is_needs_human(db):
    _repeats(db, 4)
    assert _verdict(db, _add(db, "cur"))["verdict"] == "needs_human"


def test_five_repeats_is_false_positive(db):
    _repeats(db, 5)
    v = _verdict(db, _add(db, "cur"))
    assert v["verdict"] == "false_positive"
    assert v["confidence"] == 0.80


def test_repeats_match_on_same_entity_set_with_other_title(db):
    ents = [{"type": "user", "value": "svc_bkp"}]
    for i in range(5):
        _add(db, f"ent{i}", title=f"other {i}", ents=ents, age=timedelta(hours=2))
    alert = _add(db, "cur", title="unique title", ents=ents)
    assert _verdict(db, alert)["verdict"] == "false_positive"


def test_repeats_older_than_24h_do_not_count(db):
    _repeats(db, 6, age=timedelta(hours=25))
    assert _verdict(db, _add(db, "cur"))["verdict"] == "needs_human"


def test_repeats_blocked_by_tp_history(db):
    _closed(db, "r1", 0, n_tp=1)
    _repeats(db, 5)
    assert _verdict(db, _add(db, "cur"))["verdict"] == "needs_human"


def test_repeats_from_other_rule_do_not_count(db):
    _repeats(db, 5, rule="r2")
    assert _verdict(db, _add(db, "cur"))["verdict"] == "needs_human"


# ---- (d) related OPEN alerts from other rules sharing an entity ----------------

IP = [{"type": "ip", "value": "1.2.3.4"}]


def _rel(db, aid, *, rule="other", ents=IP, status="new", age=timedelta(hours=1)):
    return _add(db, aid, rule=rule, severity="high", ents=ents, status=status, age=age,
                title=f"rel {aid}")


def test_one_related_alert_is_not_enough(db):
    _rel(db, "rel1")
    alert = _add(db, "cur", severity="high", ents=IP)
    v = _verdict(db, alert, entities=[_ip("1.2.3.4")])
    assert v["verdict"] == "needs_human"
    assert v["confidence"] == 0.50


def test_two_related_alerts_is_true_positive(db):
    _rel(db, "rel1")
    _rel(db, "rel2", status="active")
    alert = _add(db, "cur", severity="high", ents=IP)
    v = _verdict(db, alert, entities=[_ip("1.2.3.4")])
    assert v["verdict"] == "true_positive"
    assert v["confidence"] == 0.75
    assert "escalate_alert" in v["recommended_actions"]


def test_related_on_same_rule_do_not_count(db):
    _rel(db, "rel1", rule="r1")
    _rel(db, "rel2", rule="r1")
    alert = _add(db, "cur", severity="high", ents=IP)
    assert _verdict(db, alert, entities=[_ip("1.2.3.4")])["verdict"] == "needs_human"


def test_closed_related_alerts_do_not_count(db):
    _rel(db, "rel1", status="closed_fp")
    _rel(db, "rel2", status="closed_tp")
    alert = _add(db, "cur", severity="high", ents=IP)
    assert _verdict(db, alert, entities=[_ip("1.2.3.4")])["verdict"] == "needs_human"


def test_related_older_than_24h_do_not_count(db):
    _rel(db, "rel1", age=timedelta(hours=25))
    _rel(db, "rel2", age=timedelta(hours=25))
    alert = _add(db, "cur", severity="high", ents=IP)
    assert _verdict(db, alert, entities=[_ip("1.2.3.4")])["verdict"] == "needs_human"


def test_related_ip_substring_does_not_match(db):
    _rel(db, "rel1", ents=[{"type": "ip", "value": "1.2.3.45"}])
    _rel(db, "rel2", ents=[{"type": "ip", "value": "11.2.3.4"}])
    alert = _add(db, "cur", severity="high", ents=IP)
    assert _verdict(db, alert, entities=[_ip("1.2.3.4")])["verdict"] == "needs_human"


def test_critical_with_two_related_is_true_positive(db):
    _rel(db, "rel1")
    _rel(db, "rel2")
    alert = _add(db, "cur", severity="critical", ents=IP)
    assert _verdict(db, alert, entities=[_ip("1.2.3.4")])["verdict"] == "true_positive"


# ---- (c) entity reputation, severity, benign-style rule -----------------------

def test_high_rep_80_boundary_high_severity_is_needs_human(db):
    alert = _add(db, "cur", severity="high")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=80)])
    assert (v["verdict"], v["confidence"]) == ("needs_human", 0.50)


def test_high_rep_81_high_severity_is_true_positive(db):
    alert = _add(db, "cur", severity="high")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=81)])
    assert (v["verdict"], v["confidence"]) == ("true_positive", 0.75)


def test_high_rep_81_medium_severity_stays_needs_human(db):
    alert = _add(db, "cur", severity="medium")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=81)])
    assert (v["verdict"], v["confidence"]) == ("needs_human", 0.80)


def test_critical_low_rep_is_needs_human_080(db):
    alert = _add(db, "cur", severity="critical")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=50)])
    assert (v["verdict"], v["confidence"]) == ("needs_human", 0.80)
    assert v["monitor_entities"] == [{"type": "ip", "value": "10.9.3.3"}]


def test_medium_ambiguous_is_needs_human_050(db):
    v = _verdict(db, _add(db, "cur", severity="medium"), entities=[_ip("10.0.0.1")])
    assert (v["verdict"], v["confidence"]) == ("needs_human", 0.50)
    assert v["recommended_actions"] == ["collect_more_evidence", "review_manually"]


def test_benign_style_rep_20_boundary(db):
    alert = _add(db, "cur", severity="low")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=20, fp=5)])
    assert (v["verdict"], v["confidence"]) == ("false_positive", 0.85)


def test_benign_style_rep_21_boundary(db):
    alert = _add(db, "cur", severity="low")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=21, fp=5)])
    assert (v["verdict"], v["confidence"]) == ("needs_human", 0.50)


def test_low_rep_without_fp_history_is_needs_human(db):
    alert = _add(db, "cur", severity="low")
    v = _verdict(db, alert, entities=[_ip("10.0.0.1", rep=10, fp=0)])
    assert v["verdict"] == "needs_human"


def test_summary_names_the_signals(db):
    _closed(db, "r1", 5)
    v = _verdict(db, _add(db, "cur"))
    assert "rule_closed_fp=5" in v["summary"]
    assert v["summary"].endswith("-> false_positive (rule FP ratio 5/5)")
