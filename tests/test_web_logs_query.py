"""Logs page: time-range handling, display limit, and /api/query behaviour (2026-10-14 rework).

Run: .venv/bin/python -m pytest -q tests/test_web_logs_query.py
Bug these pin: the time picker used to append `| where TimeGenerated > ago(..)` after the user's query, which
broke on summarize (Binder Error) and on tables without TimeGenerated.
"""
from __future__ import annotations

import os
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow
from siempl.web._logs_query import (
    DISPLAY_LIMIT_DEFAULT,
    apply_time_range,
    normalize_time_range,
    with_display_limit,
)
from siempl.web.routes_logs import _parse_query_body

TABLES = frozenset({"AuthEvents", "NetworkEvents"})


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_logsq_") as td:
        os.environ["SIEMPL_HOME"] = td
        database = Database(str(Path(td) / "t.duckdb"))
        yield database
        database.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db))


def _seed_auth(db: Database, fresh: int, old: int) -> None:
    now = utcnow()
    rows = [{"TimeGenerated": now, "UserName": f"new{i}", "Message": "m", "RawEvent": "r"} for i in range(fresh)]
    rows += [{"TimeGenerated": now - timedelta(days=2), "UserName": f"old{i}", "Message": "m", "RawEvent": "r"}
             for i in range(old)]
    db.insert_events("AuthEvents", rows)


def _post(client: TestClient, **body):
    return client.post("/api/query", json=body)


# ---------------------------------------------------------------- pure time-range rule

@pytest.mark.parametrize(
    ("query", "expected_kql"),
    [
        ("AuthEvents | summarize c=count() by UserName",
         "AuthEvents | where TimeGenerated > ago(1h) | summarize c=count() by UserName"),
        ("AuthEvents | take 5", "AuthEvents | where TimeGenerated > ago(1h) | take 5"),
        ("AuthEvents", "AuthEvents | where TimeGenerated > ago(1h)"),
        ("// note\nAuthEvents | take 5", "// note\nAuthEvents | where TimeGenerated > ago(1h) | take 5"),
        ("AuthEvents\n| where EventResult == 'failure'",
         "AuthEvents | where TimeGenerated > ago(1h)\n| where EventResult == 'failure'"),
    ],
)
def test_time_range_inserted_after_leading_table(query, expected_kql):
    prep = apply_time_range(query, "1h", TABLES)
    assert prep.kql == expected_kql
    assert prep.time_range == "1h"
    assert prep.note == ""
    assert prep.source == "AuthEvents"


@pytest.mark.parametrize("query", ["alerts | take 3", "entities | take 1", "NoSuchTable | take 5"])
def test_time_range_not_applied_to_tables_without_timegenerated(query):
    prep = apply_time_range(query, "24h", TABLES)
    assert prep.kql == query
    assert prep.time_range == ""
    assert "not an event table" in prep.note


def test_time_range_not_applied_to_let_statements():
    query = "let x = AuthEvents; x | take 1"
    prep = apply_time_range(query, "1h", TABLES)
    assert prep.kql == query
    assert "let statements" in prep.note


def test_all_time_leaves_query_untouched():
    query = "AuthEvents | summarize c=count() by UserName"
    prep = apply_time_range(query, "", TABLES)
    assert prep.kql == query
    assert prep.time_range == "" and prep.note == ""


@pytest.mark.parametrize("value", ["", None, "  ", "1h", "7d"])
def test_normalize_time_range_accepts_supported_values(value):
    assert normalize_time_range(value) == (value or "").strip()


@pytest.mark.parametrize("value", ["5y", "1 h", "1h; drop table x", "ago(1h)"])
def test_normalize_time_range_rejects_anything_else(value):
    with pytest.raises(ValueError, match="unknown time range"):
        normalize_time_range(value)


def test_display_limit_appended_unless_query_has_take():
    assert with_display_limit("AuthEvents", 50) == ("AuthEvents | take 50", 50)
    assert with_display_limit("AuthEvents | take 7", 50) == ("AuthEvents | take 7", None)
    assert with_display_limit("AuthEvents", None) == ("AuthEvents", None)


def test_parse_query_body_defaults_and_limits():
    req = _parse_query_body({"query": " AuthEvents ", "time_range": "1h"})
    assert (req.query, req.time_range, req.limit) == ("AuthEvents", "1h", DISPLAY_LIMIT_DEFAULT)
    assert _parse_query_body({"query": "A", "limit": 0}).limit is None
    assert _parse_query_body({"query": "A", "limit": True}).limit == DISPLAY_LIMIT_DEFAULT


@pytest.mark.parametrize("body", [["not", "a", "dict"], {"query": "   "}, {"query": "A", "time_range": "9z"}])
def test_parse_query_body_rejects_bad_input(body):
    with pytest.raises(ValueError):
        _parse_query_body(body)


# ---------------------------------------------------------------- /api/query end to end

def test_summarize_with_time_range_runs_and_filters(client, db):
    """The reported bug: summarize + time range used to fail with a Binder Error."""
    _seed_auth(db, fresh=3, old=2)
    all_time = _post(client, query="AuthEvents | summarize n=count()", limit=0).json()
    last_1h = _post(client, query="AuthEvents | summarize n=count()", limit=0, time_range="1h").json()
    assert "error" not in last_1h
    assert all_time["rows"] == [[5]]
    assert last_1h["rows"] == [[3]]
    assert last_1h["time_range"] == "1h"
    assert last_1h["requested_time_range"] == "1h"
    assert last_1h["time_range_note"] == ""
    assert "INTERVAL 1 HOUR" in last_1h["sql"]  # the filter sits before the aggregate, not after it


def test_time_range_on_table_without_timegenerated_runs_with_note(client):
    r = _post(client, query="alerts | take 3", limit=5, time_range="1h")
    assert r.status_code == 200
    data = r.json()
    assert "alert_id" in data["columns"]
    assert data["time_range"] == ""
    assert data["requested_time_range"] == "1h"
    assert "not an event table" in data["time_range_note"]


def test_unknown_table_returns_real_error_text(client):
    r = _post(client, query="NoSuchTable | take 5", limit=50, time_range="1h")
    assert r.status_code == 400
    assert r.json()["error"].startswith("unknown table 'NoSuchTable'")


def test_parse_error_returns_real_error_text(client):
    r = _post(client, query="AuthEvents | where | take 5", limit=50)
    assert r.status_code == 400
    assert r.json()["error"].startswith("KQL parse error")


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"query": "AuthEvents", "time_range": "5y"}, "unknown time range '5y'"),
        ({"query": "   "}, "Empty query"),
    ],
)
def test_bad_request_is_json_400(client, kwargs, message):
    r = _post(client, **kwargs)
    assert r.status_code == 400
    assert r.json()["error"].startswith(message)


def test_non_json_body_is_json_400(client):
    r = client.post("/api/query", content=b"not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    assert "error" in r.json()


def test_display_limit_respected_with_time_range(client, db):
    _seed_auth(db, fresh=12, old=0)
    data = _post(client, query="AuthEvents | project UserName", limit=5, time_range="24h").json()
    assert len(data["rows"]) == 5
    assert data["limit_applied"] == 5
    assert data["truncated"] is False


def test_logs_page_deep_link_with_time_range_and_error(client, db):
    _seed_auth(db, fresh=2, old=0)
    ok = client.get("/logs", params={"q": "AuthEvents | summarize c=count()", "tr": "1h"})
    assert ok.status_code == 200
    assert '<option value="1h" selected>' in ok.text
    assert 'id="initial-result"' in ok.text and '"requested_time_range": "1h"' in ok.text
    bad = client.get("/logs", params={"q": "NoSuchTable", "tr": "1h"})
    assert bad.status_code == 200
    assert "unknown table &#39;NoSuchTable&#39;" in bad.text
    assert 'id="query-error" class="query-error" role="alert" style="display:block"' in bad.text
