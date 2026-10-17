"""Logs page export: complete CSV/JSON, 100k cap reported in headers, same time-range rule as the screen.

Run: .venv/bin/python -m pytest -q tests/test_web_logs_export.py
Bugs these pin: export used window.open (no time range, no limit, raw JSON on error) and the executor's
default 10k cap silently truncated 'full' exports. The cap test inserts 100,005 rows, so it takes a few seconds.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database, utcnow
from siempl.web._logs_export import csv_bytes, export_filename, json_bytes, json_cell
from siempl.web._logs_query import EXPORT_HARD_CAP


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_logsx_") as td:
        os.environ["SIEMPL_HOME"] = td
        database = Database(str(Path(td) / "t.duckdb"))
        yield database
        database.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db))


def _export(client: TestClient, query: str, fmt: str = "csv", time_range: str = ""):
    return client.post("/api/export", json={"query": query, "format": fmt, "time_range": time_range})


def _csv_rows(body: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(body.decode("utf-8"), newline="")))


# ---------------------------------------------------------------- encoding helpers

def test_csv_has_header_and_escapes_cells():
    cols = ["Name", "Note"]
    rows = [["a,b", 'say "hi"'], ["line1\nline2", None], [3, True]]
    parsed = _csv_rows(csv_bytes(cols, rows))
    assert parsed == [["Name", "Note"], ["a,b", 'say "hi"'], ["line1\nline2", ""], ["3", "True"]]


def test_csv_empty_result_still_has_header():
    assert _csv_rows(csv_bytes(["A", "B"], [])) == [["A", "B"]]


def test_json_bytes_maps_columns_and_keeps_types():
    body = json_bytes(["n", "t"], [[1, datetime(2026, 10, 14, 1, 2, 3)], [None, "x"]])
    assert json.loads(body) == [{"n": 1, "t": "2026-10-14T01:02:03"}, {"n": None, "t": "x"}]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), (5, 5), ("s", "s"), (float("nan"), None), (float("inf"), None), (1.5, 1.5)],
)
def test_json_cell_is_json_safe(value, expected):
    assert json_cell(value) == expected


def test_export_filename_is_sanitized_and_stamped():
    when = datetime(2026, 10, 14, 1, 2, 3, tzinfo=UTC)
    assert export_filename("Auth;Events", "csv", when) == "siempl-AuthEvents-20261014-010203.csv"
    assert export_filename("", "json", when) == "siempl-query-20261014-010203.json"


# ---------------------------------------------------------------- endpoint behaviour

def test_export_csv_is_complete_with_header(client, db):
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": f"u{i}", "Message": "m",
                                     "RawEvent": "r"} for i in range(250)])
    r = _export(client, "AuthEvents | project UserName")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert re.fullmatch(r'attachment; filename="siempl-AuthEvents-\d{8}-\d{6}\.csv"',
                        r.headers["content-disposition"])
    parsed = _csv_rows(r.content)
    assert parsed[0] == ["UserName"]
    assert len(parsed) == 251
    assert r.headers["x-export-rows"] == "250"
    assert r.headers["x-export-truncated"] == "false"
    assert r.headers["x-export-row-cap"] == str(EXPORT_HARD_CAP)


def test_export_csv_round_trips_awkward_values(client, db):
    msg = 'quote " comma , newline\nend'
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": "bob", "Message": msg,
                                     "RawEvent": "r"}])
    parsed = _csv_rows(_export(client, "AuthEvents | project UserName, Message").content)
    assert parsed == [["UserName", "Message"], ["bob", msg]]


def test_export_json_is_complete_list(client, db):
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": f"u{i}", "RawEvent": "r"}
                                    for i in range(7)])
    r = _export(client, "AuthEvents | project UserName", fmt="json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert [row["UserName"] for row in json.loads(r.content)] == [f"u{i}" for i in range(7)]


def test_export_get_and_post_agree(client, db):
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": "a", "RawEvent": "r"}])
    via_get = client.get("/api/export", params={"query": "AuthEvents | project UserName", "format": "csv"})
    via_post = _export(client, "AuthEvents | project UserName")
    assert via_get.content == via_post.content == b"UserName\r\na\r\n"


def test_export_applies_time_range_like_the_screen(client, db):
    now = utcnow()
    db.insert_events("AuthEvents", [
        {"TimeGenerated": now, "UserName": "fresh", "RawEvent": "r"},
        {"TimeGenerated": now - timedelta(days=2), "UserName": "stale", "RawEvent": "r"},
    ])
    everything = _csv_rows(_export(client, "AuthEvents | project UserName").content)
    last_hour = _export(client, "AuthEvents | project UserName", time_range="1h")
    assert len(everything) == 3
    assert _csv_rows(last_hour.content) == [["UserName"], ["fresh"]]
    assert last_hour.headers["x-time-range-applied"] == "1h"


def test_export_summarize_with_time_range_works(client, db):
    """The export used to run the query without the time range; summarize + range must now export cleanly."""
    now = utcnow()
    db.insert_events("AuthEvents", [{"TimeGenerated": now, "UserName": "x", "RawEvent": "r"},
                                    {"TimeGenerated": now, "UserName": "x", "RawEvent": "r"},
                                    {"TimeGenerated": now, "UserName": "y", "RawEvent": "r"}])
    r = _export(client, "AuthEvents | summarize c=count() by UserName", time_range="24h")
    assert r.status_code == 200
    assert _csv_rows(r.content) == [["UserName", "c"], ["x", "2"], ["y", "1"]]


def test_export_note_header_when_range_not_applicable(client, db):
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": "x", "RawEvent": "r"}])
    r = _export(client, "alerts | take 1", time_range="1h")
    assert r.status_code == 200
    assert r.headers["x-time-range-applied"] == ""
    assert "not an event table" in r.headers["x-time-range-note"].replace("%20", " ")


def test_export_full_result_is_capped_and_says_so(client, db):
    """Cap is EXPORT_HARD_CAP (100,000). A larger result is cut there and flagged in headers, not silently."""
    db.execute(
        'INSERT INTO "AuthEvents" (TimeGenerated, UserName, Message, RawEvent) '
        "SELECT now(), 'u' || range::VARCHAR, 'm', 'r' FROM range(?)",
        [EXPORT_HARD_CAP + 5],
    )
    r = _export(client, "AuthEvents | project UserName")
    assert r.status_code == 200
    assert r.headers["x-export-truncated"] == "true"
    assert r.headers["x-export-rows"] == str(EXPORT_HARD_CAP)
    assert len(_csv_rows(r.content)) == EXPORT_HARD_CAP + 1  # + header


def test_export_user_take_is_respected_not_capped(client, db):
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": f"u{i}", "RawEvent": "r"}
                                    for i in range(20)])
    r = _export(client, "AuthEvents | project UserName | take 3")
    assert len(_csv_rows(r.content)) == 4
    assert r.headers["x-export-truncated"] == "false"


@pytest.mark.parametrize(
    ("query", "fmt", "tr", "message"),
    [
        ("NoSuchTable", "csv", "", "unknown table 'NoSuchTable'"),
        ("AuthEvents | where | take 5", "csv", "", "KQL parse error"),
        ("AuthEvents", "xml", "", "unsupported export format"),
        ("   ", "csv", "", "Empty query"),
        ("AuthEvents", "csv", "5y", "unknown time range"),
    ],
)
def test_export_errors_are_json_400_not_downloads(client, query, fmt, tr, message):
    r = _export(client, query, fmt=fmt, time_range=tr)
    assert r.status_code == 400
    assert r.headers["content-type"].startswith("application/json")
    assert message in r.json()["error"]
    assert "content-disposition" not in r.headers


def test_export_is_audited(client, db):
    db.insert_events("AuthEvents", [{"TimeGenerated": utcnow(), "UserName": "x", "RawEvent": "r"}])
    _export(client, "AuthEvents | project UserName | take 1")
    rows = db.query("SELECT * FROM SiemplAudit WHERE Action = 'query.export'")
    assert rows, "export must leave an audit row"
