"""Rules x alerts: list counts (Alerts / Open columns), /alerts?rule= filter and the rule detail panel."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database
from siempl.web import create_app
from siempl.web._rules_alerts import rule_alert_counts


def _add_rule(db, rule_id, name, origin="manual"):
    db.execute(
        "INSERT INTO rules(rule_id,name,description,severity,query,tables,enabled,origin) VALUES (?,?,?,?,?,?,?,?)",
        [rule_id, name, "desc", "high", "AuthEvents | take 1", ["AuthEvents"], True, origin])


def _add_alerts(db, rule_id, statuses, prefix="a"):
    for i, status in enumerate(statuses):
        db.execute(
            "INSERT INTO alerts(alert_id,rule_id,title,severity,status,created_at,alert_number) "
            "VALUES (?,?,?,?,?,now(),(SELECT coalesce(max(alert_number),0)+1 FROM alerts))",
            [f"{prefix}{rule_id}-{i}", rule_id, f"{prefix} title {i}", "high", status])


@pytest.fixture()
def env(tmp_path):
    db = Database(tmp_path / "t.duckdb")
    _add_rule(db, "rule_a", "Alpha Rule", origin="sigma")
    _add_rule(db, "rule_b", "Beta Rule")
    _add_rule(db, "rule_c", "Gamma Rule")
    _add_alerts(db, "rule_a", ["new", "active", "closed_tp", "closed_fp", "new"])
    _add_alerts(db, "rule_b", ["closed_tp"])
    return db, TestClient(create_app(db))


def _row_for(html: str, name: str) -> str:
    """The table row (<tr>...</tr>) that contains the rule's name link."""
    rows = re.findall(r"<tr>.*?</tr>", html, flags=re.S)
    matches = [row for row in rows if f">{name}</a>" in row]
    assert len(matches) == 1, f"expected one row for {name}, got {len(matches)}"
    return matches[0]


def test_list_has_alerts_and_open_columns_and_no_format_or_origin(env):
    _, c = env
    html = c.get("/rules").text
    header = re.search(r"<thead>(.*?)</thead>", html, flags=re.S).group(1)
    assert "Alerts" in header and "Open" in header
    assert "Format" not in header and "Origin" not in header
    assert "Sigma-imported" not in html and "KQL manual" not in html


def test_list_shows_total_and_open_counts_per_rule(env):
    _, c = env
    alpha = _row_for(c.get("/rules").text, "Alpha Rule")
    assert 'href="/alerts?rule=rule_a"' in alpha
    assert '>5</a>' in alpha          # total alerts for the rule
    assert "<td>3</td>" in alpha     # open = 2 new + 1 active
    beta = _row_for(c.get("/rules").text, "Beta Rule")
    assert '>1</a>' in beta and "<td>0</td>" in beta
    gamma = _row_for(c.get("/rules").text, "Gamma Rule")
    assert '>0</a>' in gamma and "<td>0</td>" in gamma


def test_counts_come_from_one_grouped_query_and_scale(env):
    db, c = env
    _add_alerts(db, "rule_b", ["new"] * 800, prefix="bulk")
    counts = rule_alert_counts(db)
    assert counts["rule_b"] == {"total": 801, "open": 800}  # 1 closed_tp + 800 new
    assert counts["rule_a"] == {"total": 5, "open": 3}
    assert "rule_c" not in counts
    assert c.get("/rules").status_code == 200


def test_rule_filter_on_alerts_list_and_chip(env):
    _, c = env
    r = c.get("/alerts?rule=rule_a&status=all")
    assert r.status_code == 200
    assert r.text.count('class="alert-row"') == 5
    assert "Rule: Alpha Rule" in r.text
    assert 'name="rule" value="rule_a"' in r.text
    clear = re.search(r'href="(/alerts[^"]*)" aria-label="Clear rule filter"', r.text)
    assert clear and "rule=" not in clear.group(1)


def test_rule_filter_combines_with_status_and_unknown_rule(env):
    _, c = env
    assert c.get("/alerts?rule=rule_a").text.count('class="alert-row"') == 3
    assert c.get("/alerts?rule=rule_b").text.count('class="alert-row"') == 0
    unknown = c.get("/alerts?rule=nope")
    assert unknown.status_code == 200 and "Rule: nope" in unknown.text


def test_rule_filter_is_bound_not_spliced(env):
    _, c = env
    r = c.get("/alerts?rule=x' OR '1'='1&status=all")
    assert r.status_code == 200
    assert r.text.count('class="alert-row"') == 0


def test_no_chip_without_rule_filter(env):
    _, c = env
    assert "Rule: " not in c.get("/alerts").text


def test_detail_panel_shows_counts_and_latest_alerts(env):
    _, c = env
    html = c.get("/rules/rule_a").text
    assert "Alerts from this rule (5)" in html
    assert 'href="/alerts?rule=rule_a&amp;status=all"' in html or 'href="/alerts?rule=rule_a&status=all"' in html
    assert "<svg" in html and "chart-bar" in html
    assert "Recent Alerts" not in html
    assert "Alerts from this rule (5)" in html and html.count('class="link">#') == 5
    assert "a title 0" in html and "Closed - True Positive" in html


def test_detail_panel_links_each_alert_to_its_page(env):
    db, c = env
    aid = db.query_one("SELECT alert_id FROM alerts WHERE rule_id='rule_a' ORDER BY alert_number LIMIT 1")["alert_id"]
    assert f'href="/alerts/{aid}"' in c.get("/rules/rule_a").text


def test_detail_panel_empty_rule(env):
    _, c = env
    html = c.get("/rules/rule_c").text
    assert "Alerts from this rule (0)" in html
    assert "No alerts from this rule yet." in html


def test_detail_panel_caps_rows_at_25(env):
    db, c = env
    _add_alerts(db, "rule_c", ["new"] * 30, prefix="cap")
    html = c.get("/rules/rule_c").text
    assert html.count('class="link">#') == 25
    assert "Alerts from this rule (30)" in html
