"""Overview page (/): empty and seeded render, range fallback, panels, stacked chart escaping.

Run: .venv/bin/python -m pytest tests/test_web_overview.py -q
"""
from __future__ import annotations

import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database
from siempl.schema import DATA_TABLES
from siempl.web import _overview_data as overview_data
from siempl.web._svg_charts import stacked_bar_svg

PANEL_TITLES = (
    "Events per hour", "Open alerts by severity", "Source health", "Alerts created per hour",
    "Top rules by alerts", "Top entities by reputation", "Events by table", "Recent agent runs",
    "AI spend and approvals",
)

@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_overview_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        database = Database(str(Path(td) / "t.duckdb"))
        database.init_schema()
        yield database
        database.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db), follow_redirects=False)


def _db_now(db) -> datetime:
    """DuckDB's local clock, the one alerts and agent runs are stamped with."""
    return db.query_one("SELECT now()::TIMESTAMP AS n")["n"]

def seed(db) -> None:
    """One event, two alerts (one open), one failed agent run, one rule, one entity, one recommendation."""
    now = _db_now(db)
    table = next(iter(DATA_TABLES))
    db.execute(f'INSERT INTO "{table}"("TimeGenerated") VALUES (?)', [datetime.now(UTC).replace(tzinfo=None)])
    db.execute("INSERT INTO rules(rule_id,name,severity,query) VALUES (?,?,?,?)",
               ["rule_a", "Rule <b>A</b>", "high", "Syslog | take 1"])
    db.execute("INSERT INTO alerts(alert_id,rule_id,title,severity,status,created_at,updated_at,alert_number) "
               "VALUES (?,?,?,?,?,?,?,?)", ["al_1", "rule_a", "A1", "high", "new", now, now, 1])
    db.execute("INSERT INTO alerts(alert_id,rule_id,title,severity,status,created_at,updated_at,alert_number) "
               "VALUES (?,?,?,?,?,?,?,?)", ["al_2", "rule_a", "A2", "critical", "closed_tp", now, now, 2])
    db.execute("INSERT INTO agent_runs(run_id,agent,status,started_at,summary) VALUES (?,?,?,?,?)",
               ["run_1", "tuning", "error", now, "boom <i>x</i>"])
    db.execute("INSERT INTO entities(entity_id,type,value,reputation,alert_count) VALUES (?,?,?,?,?)",
               ["ip:1.2.3.4", "ip", "1.2.3.4", 90.0, 2])
    db.execute("INSERT INTO recommendations(rec_id,agent,kind,target,title,status) VALUES (?,?,?,?,?,?)",
               ["rec_1", "optimizer", "retention", "Syslog", "Shorten retention", "open"])

def test_empty_db_renders_every_panel(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.text
    assert 'class="ov-screen"' in html
    assert len(re.findall(r'<section class="ov-panel[ "]', html)) == 9
    for title in PANEL_TITLES:
        assert title in html
    assert "No agent runs yet." in html
    assert "No open alerts" in html


def test_seeded_render_shows_figures(client, db):
    seed(db)
    html = client.get("/?range=7d").text
    assert re.search(r'ov-kpi-label">Open alerts</span>\s*<span class="ov-kpi-value">1<', html)
    assert re.search(r'ov-kpi-label">Agent runs</span>\s*<span class="ov-kpi-value">1<', html)
    assert "1 failed" in html
    assert "Shorten retention" not in html  # recommendations are counted, never listed
    assert "Pending approvals" in html

def test_seeded_text_is_escaped(client, db):
    seed(db)
    html = client.get("/?range=7d").text
    assert "<b>A</b>" not in html and "Rule &lt;b&gt;A&lt;/b&gt;" in html
    assert "<i>x</i>" not in html and "boom &lt;i&gt;x&lt;/i&gt;" in html
    assert 'href="/entities/ip%3A1.2.3.4"' in html

@pytest.mark.parametrize("raw, active", [("1h", "1h"), ("7d", "7d"), ("24h", "24h"),
                                         ("bogus", "24h"), ("", "24h")])
def test_range_param_falls_back_to_24h(client, raw, active):
    html = client.get("/", params={"range": raw}).text
    assert f'range-tab active" href="/?range={active}">{active}</a>' in html


def test_data_range_fallback_and_buckets(db):
    seed(db)
    assert overview_data.build_overview(db, "nonsense")["range"] == "24h"
    out = overview_data.build_overview(db, "7d")
    assert sum(out["alert_buckets"]["series"]["high"]) == 1
    assert out["open_by_severity"] == {"critical": 0, "high": 1, "medium": 0, "low": 0, "informational": 0}
    assert out["top_rules"][0] == {"name": "Rule <b>A</b>", "rule_id": "rule_a", "count": 2}
    assert out["sources"]["total"] == 0

def test_stacked_escapes_labels_and_aria():
    svg = stacked_bar_svg(["<x>"], [("<s>", [3], "red")], aria_label="<a>")
    assert "<s>" not in svg and "<x>" not in svg and "<a>" not in svg
    assert "&lt;s&gt;" in svg and "&lt;x&gt;" in svg and "&lt;a&gt;" in svg


def test_stacked_empty_returns_placeholder():
    empty = stacked_bar_svg([], [], empty_label="nothing <here>")
    assert "chart-empty" in empty and "nothing &lt;here&gt;" in empty and "<rect" not in empty
    zeros = stacked_bar_svg(["a"], [("s", [0], "red")])
    assert "chart-empty" in zeros and "<rect" not in zeros


def test_stacked_rejects_ragged_input():
    with pytest.raises(ValueError):
        stacked_bar_svg(["a", "b"], [("s", [1], "red")])
