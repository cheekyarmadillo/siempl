"""Scenario check: heuristic triage (AI off, auto_close policy) against scenarios_manifest.json."""

import pytest

from siempl.agents.triage import TriageAgent
from siempl.db import Database
from siempl.testdata.scenarios import load_scenarios, scenario_manifest

# Chain alerts with >= 2 related open alerts from other rules (kill-chain signal).
CHAIN_TP = {
    "scn_bf_success_after_failures", "scn_bf_encoded_powershell", "scn_bf_new_local_admin",
    "scn_lat_ntlm_fanout", "scn_lat_smb_admin_share",
    "scn_exfil_large_outbound", "scn_exfil_dns_tunnel",
}


@pytest.fixture(scope="module")
def triaged(tmp_path_factory):
    db = Database(str(tmp_path_factory.mktemp("scn") / "s.duckdb"))
    db.set_setting("ai_enabled", False)
    load_scenarios(db)
    db.execute("DELETE FROM agent_policy WHERE agent='triage'")
    db.execute("INSERT INTO agent_policy VALUES ('triage','global','*','auto_close',TRUE,TRUE,FALSE,TRUE)")
    out = []
    seen: dict[str, int] = {}
    for sc in scenario_manifest()["scenarios"]:
        for entry in sc.get("alerts", []):
            rid = entry["rule_id"]
            rows = db.query("SELECT alert_id FROM alerts WHERE rule_id=? ORDER BY created_at", [rid])
            idx = seen.get(rid, 0)
            seen[rid] = idx + 1
            aid = rows[idx]["alert_id"]
            res = TriageAgent(db, None, dry_run=False).run(input_ref=aid, alert_id=aid)
            status = db.query_one("SELECT status FROM alerts WHERE alert_id=?", [aid])["status"]
            out.append({"entry": entry, "rule_id": rid, "res": res, "status": status,
                        "verdict": res.output.get("verdict"),
                        "injection_detected": bool(res.output.get("injection_detected"))})
    return out

def test_every_run_is_ok(triaged):
    assert len(triaged) == 21
    assert all(t["res"].status == "ok" for t in triaged)


def test_noisy_false_positives_close_as_fp(triaged):
    # The scenario rule already has closed-FP history, so the verdict carries 0.90 and auto-closes.
    noisy = [t for t in triaged if t["rule_id"] == "scn_fp_any_failed_logon"]
    assert len(noisy) == 8
    for t in noisy:
        assert t["verdict"] == "false_positive", t
        assert t["status"] == "closed_fp", t


def test_repetition_only_false_positive_waits_for_a_human(tmp_path):
    # No closed history, only repeats: verdict false_positive at 0.80 (< 0.85 close threshold), alert stays new.
    db = Database(str(tmp_path / "r.duckdb"))
    db.set_setting("ai_enabled", False)
    load_scenarios(db)
    db.execute("DELETE FROM agent_policy WHERE agent='triage'")
    db.execute("INSERT INTO agent_policy VALUES ('triage','global','*','auto_close',TRUE,TRUE,FALSE,TRUE)")
    db.execute("UPDATE alerts SET status='new', verdict=NULL WHERE rule_id='scn_fp_any_failed_logon'")
    aid = db.query_one("SELECT alert_id FROM alerts WHERE rule_id='scn_fp_any_failed_logon' LIMIT 1")["alert_id"]
    res = TriageAgent(db, None, dry_run=False).run(input_ref=aid, alert_id=aid)
    assert res.output["verdict"] == "false_positive" and res.output["confidence"] == 0.8
    assert db.query_one("SELECT status FROM alerts WHERE alert_id=?", [aid])["status"] == "new"


def test_expected_true_positives_never_closed_fp(triaged):
    for t in triaged:
        e = t["entry"]
        if e["expected_triage"] == "true_positive" and not e["injection_flagged"]:
            assert t["verdict"] in ("true_positive", "needs_human"), t
            assert t["status"] != "closed_fp", t


def test_chain_alerts_classify_as_true_positive(triaged):
    chain = [t for t in triaged if t["rule_id"] in CHAIN_TP]
    assert len(chain) == len(CHAIN_TP)
    for t in chain:
        assert t["verdict"] == "true_positive", t
        assert t["status"] == "active", t  # escalated: confidence 0.75 < close threshold


def test_single_related_password_spray_stays_needs_human(triaged):
    spray = next(t for t in triaged if t["rule_id"] == "scn_bf_password_spray")
    assert spray["verdict"] == "needs_human", spray


def test_expected_needs_human_end_needs_human(triaged):
    for t in triaged:
        if t["entry"]["expected_triage"] == "needs_human":
            assert t["verdict"] == "needs_human", t
            assert t["status"] != "closed_fp", t


def test_injection_flagged_never_closed_and_detected(triaged):
    flagged = [t for t in triaged if t["entry"]["injection_flagged"]]
    assert len(flagged) == 3
    for t in flagged:
        assert t["injection_detected"] is True, t
        assert t["verdict"] == "needs_human", t
        assert t["status"] not in ("closed_fp", "closed_tp"), t
