"""Tests for the ingestion overview: line_svg escaping/empty/ragged input, bucket alignment, range fallback, render."""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database
from siempl.web import create_app
from siempl.web._ingestion_overview import (
    RANGES,
    _bucket_starts,
    _floor,
    build_overview,
    parse_range,
)
from siempl.web._svg_charts import EMPTY_LINE_LABEL, _nice_max, line_svg

NOW = datetime(2026, 10, 14, 13, 7, 42)


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.duckdb"))
    os.environ["SIEMPL_HOME"] = str(tmp_path)
    yield d
    d.close()


# ---- line_svg ---------------------------------------------------------------

def test_line_svg_escapes_labels_and_colour():
    svg = line_svg([("<b>x</b>", [1, 2, 3], "red\" onload=\"x")], ["<i>a</i>", "b", "c"], aria_label="<script>")
    assert "<script>" not in svg and "<b>x</b>" not in svg and "<i>a</i>" not in svg
    assert "&lt;b&gt;x&lt;/b&gt;" in svg
    assert "&lt;i&gt;a&lt;/i&gt;" in svg
    assert "&lt;script&gt;" in svg
    assert 'onload="x"' not in svg


def test_line_svg_empty_and_zero_series_return_placeholder():
    for series in ([], [("a", [], "red")], [("a", [0, 0, 0], "red")]):
        svg = line_svg(series)
        assert "chart-empty" in svg
        assert EMPTY_LINE_LABEL in svg
        assert "<polyline" not in svg


def test_line_svg_ragged_series_raises():
    with pytest.raises(ValueError, match="same length"):
        line_svg([("a", [1, 2], "red"), ("b", [1, 2, 3], "blue")])


def test_line_svg_x_labels_must_match_length():
    with pytest.raises(ValueError, match="x_labels"):
        line_svg([("a", [1, 2, 3], "red")], ["only one"])


def test_line_svg_single_point_and_negative_clamped():
    svg = line_svg([("a", [-5, 4], "red")], ["00:00", "01:00"])
    assert "<polyline" in svg
    assert "NaN" not in svg


def test_nice_max_rounds_up_to_clean_number():
    assert _nice_max(0) == 0
    assert _nice_max(7) == 10
    assert _nice_max(11) == 20
    assert _nice_max(2300) == 2500
    assert _nice_max(480) == 500


# ---- buckets and range parsing ---------------------------------------------

def test_floor_aligns_to_epoch_grid():
    assert _floor(datetime(2026, 10, 14, 13, 7, 42), timedelta(minutes=5)) == datetime(2026, 10, 14, 13, 5)
    assert _floor(datetime(2026, 10, 14, 13, 7, 42), timedelta(hours=6)) == datetime(2026, 10, 14, 12, 0)


def test_bucket_starts_cover_window_and_are_aligned():
    for key, spec in RANGES.items():
        starts = _bucket_starts(NOW, spec)
        step = spec["bucket"]
        assert all((s - datetime(1970, 1, 1)) % step == timedelta(0) for s in starts), key
        assert starts[-1] <= NOW < starts[-1] + step
        assert starts[0] <= NOW - spec["window"] < starts[0] + step


def test_parse_range_falls_back_to_24h():
    assert parse_range("1h") == "1h"
    assert parse_range("7d") == "7d"
    for bad in (None, "", "2h", "24H", "1h; drop", "<script>"):
        assert parse_range(bad) == "24h"


# ---- database-backed overview and rendering ---------------------------------

def _seed(db, now, count_by_minutes_ago):
    rows = []
    for minutes_ago, n in count_by_minutes_ago:
        for _ in range(n):
            rows.append({"TimeGenerated": now - timedelta(minutes=minutes_ago), "RawEvent": "x", "SourceId": "src_a"})
    db.insert_events("GenericEvents", rows)


def test_overview_empty_database(db):
    ov = build_overview(db, "1h", now=NOW)
    assert ov["range"] == "1h"
    assert ov["tiles"][0]["value"] == "0"
    assert "chart-empty" in ov["line_svg"]
    assert "No events in this range" in ov["bar_svg"]


def test_overview_counts_only_window(db):
    _seed(db, NOW, [(10, 3), (70, 5)])  # 70 minutes ago is outside the 1h window
    ov = build_overview(db, "1h", now=NOW)
    assert ov["tiles"][0]["value"] == "3"
    assert "GenericEvents" in ov["bar_svg"]
    assert "chart-line" in ov["line_svg"]
    assert ov["tiles"][3]["value"] == "0"


def test_overview_24h_includes_older_events(db):
    _seed(db, NOW, [(10, 3), (70, 5)])
    ov = build_overview(db, "24h", now=NOW)
    assert ov["tiles"][0]["value"] == "8"


def test_overview_bad_range_uses_24h(db):
    _seed(db, NOW, [(10, 2)])
    assert build_overview(db, "bogus", now=NOW)["range"] == "24h"
    assert build_overview(db, None, now=NOW)["range"] == "24h"


def test_overview_error_and_stale_sources(db):
    db.execute("INSERT INTO sources (source_id, name, kind, status, last_event_at) VALUES "
               "('src_ok', 'ok', 'http', 'active', ?), ('src_old', 'old', 'file', 'active', ?), "
               "('src_err', 'err', 'syslog', 'active', ?)",
               [NOW, NOW - timedelta(hours=5), NOW])
    ov = build_overview(db, "24h", error_ids=frozenset({"src_err"}), now=NOW)
    assert ov["tiles"][1]["value"] == "3"
    assert ov["tiles"][2]["value"] == "2"
    assert "1 error, 1 stale" in ov["tiles"][2]["detail"]


def test_route_renders_empty_and_seeded(db):
    client = TestClient(create_app(db))
    r = client.get("/ingestion")
    assert r.status_code == 200
    assert "Overview, last 24 hours" in r.text
    assert "ingest-overview" in r.text
    assert 'class="chart chart-line chart-empty"' in r.text
    _seed(db, datetime.now(UTC).replace(tzinfo=None), [(5, 4)])
    r = client.get("/ingestion?range=1h")
    assert r.status_code == 200
    assert "Overview, last hour" in r.text
    assert 'class="chart chart-line"' in r.text
    assert 'data-label="GenericEvents" data-value="4"' in r.text


def test_route_bad_range_falls_back_to_24h(db):
    client = TestClient(create_app(db))
    r = client.get("/ingestion?range=999y")
    assert r.status_code == 200
    assert "Overview, last 24 hours" in r.text
