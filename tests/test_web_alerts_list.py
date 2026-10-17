"""Alerts list page: charts, filters, pagination, preview deep link; SVG chart helpers."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database
from siempl.detect import create_alert
from siempl.web import create_app
from siempl.web._svg_charts import bar_svg, pie_svg


def _rule(i, sev):
    return {"rule_id": f"r{i}", "name": f"Rule {i}", "severity": sev, "frequency_minutes": 5,
            "lookback_minutes": 5, "tables": [], "entity_mappings": []}


@pytest.fixture()
def env(tmp_path):
    db = Database(tmp_path / "t.duckdb")
    sevs = ["critical", "high", "high", "medium", "low", "low", "low"]
    for i, sev in enumerate(sevs):
        create_alert(db, _rule(i, sev), rows=[["x"]], columns=["c"])
    return db, TestClient(create_app(db))


def test_list_renders_numbers_pie_and_rows(env):
    db, c = env
    r = c.get("/alerts")
    assert r.status_code == 200
    assert r.text.count('class="alert-row"') == 7
    assert "<svg" in r.text and "Open alerts by severity" in r.text
    assert "#7" in r.text and "verdict" not in r.text.lower()


def test_status_filter_default_open_and_closed(env):
    db, c = env
    aid = db.query_one("SELECT alert_id FROM alerts WHERE alert_number=1")["alert_id"]
    assert c.post(f"/api/alerts/{aid}/status", json={"status": "closed_tp"}).status_code == 200
    assert c.get("/alerts").text.count('class="alert-row"') == 6
    assert c.get("/alerts?status=closed_tp").text.count('class="alert-row"') == 1
    assert c.get("/alerts?status=all").text.count('class="alert-row"') == 7


def test_severity_filter_search_and_bad_values(env):
    db, c = env
    assert c.get("/alerts?severity=low").text.count('class="alert-row"') == 3
    assert c.get("/alerts?q=rule 3").text.count('class="alert-row"') == 1
    assert c.get("/alerts?severity=bogus&status=bogus&sort=bogus&dir=bogus").status_code == 200


def test_pagination_clamps(env):
    db, c = env
    assert c.get("/alerts?page=999").status_code == 200
    assert c.get("/alerts?page=0").status_code == 422


def test_preview_deep_link_and_fragment(env):
    db, c = env
    aid = db.query_one("SELECT alert_id FROM alerts LIMIT 1")["alert_id"]
    assert f'data-preview-id="{aid}"' in c.get(f"/alerts?preview={aid}").text
    frag = c.get("/alerts/fragments/charts")
    assert frag.status_code == 200 and 'id="alert-charts"' in frag.text
    assert c.get(f"/alerts/{aid}").status_code == 200
    assert c.get("/alerts/nope").status_code == 404


def test_chart_helpers_escape_and_empty():
    assert "No open alerts" in pie_svg([("a", 0, "red")])
    svg = pie_svg([("<script>", 3, "var(--chart-low)")])
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg
    assert "<svg" in bar_svg([("x", 2, "red"), ("y", 0, "blue")])
    assert "No alerts" in bar_svg([("x", 0, "red")])
