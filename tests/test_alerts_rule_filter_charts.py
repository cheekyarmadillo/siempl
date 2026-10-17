"""The alerts page pie/status counts follow the ?rule= filter (they used to stay global)."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow
from siempl.web.routes_alerts_api import summary_data


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_alerts_rule_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        database = Database(str(Path(td) / "t.duckdb"))
        database.init_schema()
        for i, (rule, sev, status) in enumerate([("rule_a", "high", "new"), ("rule_a", "high", "active"),
                                                 ("rule_a", "low", "closed_fp"), ("rule_b", "critical", "new"),
                                                 ("rule_b", "medium", "new"), ("rule_b", "medium", "new")]):
            database.execute(
                "INSERT INTO alerts(alert_id,rule_id,title,severity,status,description,evidence,entities,"
                "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [f"al_{i}", rule, f"Alert {i}", sev, status, "d", json.dumps([]), json.dumps([]), utcnow(), utcnow()])
        yield database
        database.close()


def test_summary_data_is_global_without_rule_and_scoped_with_it(db):
    assert summary_data(db)["open_total"] == 5
    a = summary_data(db, "rule_a")
    assert a["open_total"] == 2 and a["open_by_severity"] == {"high": 2} and a["by_status"]["closed_fp"] == 1
    b = summary_data(db, "rule_b")
    assert b["open_total"] == 3 and b["by_status"]["new"] == 3
    assert summary_data(db, "nope")["open_total"] == 0


def test_summary_api_accepts_rule(db):
    from siempl.web import create_app
    client = TestClient(create_app(db))
    assert client.get("/api/alerts/summary").json()["open_total"] == 5
    assert client.get("/api/alerts/summary?rule=rule_b").json()["open_total"] == 3


def test_page_and_fragment_charts_follow_rule_and_keep_it_in_links(db):
    from siempl.web import create_app
    client = TestClient(create_app(db))
    frag = client.get("/alerts/fragments/charts?rule=rule_b").text
    assert "rule=rule_b" in frag
    page = client.get("/alerts?rule=rule_b&status=").text
    assert "rule=rule_b" in page
    glob = client.get("/alerts/fragments/charts").text
    assert "rule=rule_b" not in glob
