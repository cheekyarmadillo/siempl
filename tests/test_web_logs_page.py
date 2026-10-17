"""Logs page markup and served scripts (2026-10-14 rework).

Run: .venv/bin/python -m pytest -q tests/test_web_logs_page.py
Bugs these pin: on a fresh load the results elements only existed inside {% if columns %}, so runQuery()
threw on null and the user saw nothing. Now the container is always rendered (hidden) and JS fills it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database

NODE = shutil.which("node")


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_logspage_") as td:
        os.environ["SIEMPL_HOME"] = td
        database = Database(str(Path(td) / "t.duckdb"))
        yield database
        database.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db))


def test_fresh_load_renders_hidden_results_container(client):
    html = client.get("/logs").text
    assert 'id="query-results" class="logs-results" style="display:none"' in html
    for element_id in ("results-thead", "results-tbody", "results-summary", "query-error", "query-error-text"):
        assert f'id="{element_id}"' in html, element_id
    assert 'id="initial-result">null</script>' in html


def test_fresh_load_has_chart_and_pivot_controls(client):
    html = client.get("/logs").text
    for element_id in ("chart-panel", "chart-type", "chart-label", "chart-value", "chart-output",
                       "pivot-panel", "pivot-group", "pivot-agg", "pivot-value", "pivot-output"):
        assert f'id="{element_id}"' in html, element_id
    assert '<option value="bar">Bar</option>' in html and '<option value="pie">Pie</option>' in html
    for agg in ("count", "sum", "avg", "min", "max"):
        assert f'<option value="{agg}">{agg}</option>' in html


def test_fresh_load_time_range_select_is_all_time(client):
    html = client.get("/logs").text
    assert '<option value="" selected>All time</option>' in html
    assert '<option value="1h" selected>' not in html


def test_bad_table_shows_server_text_in_page(client):
    html = client.get("/logs", params={"q": "NoSuchTable | take 5"}).text
    assert "unknown table &#39;NoSuchTable&#39;" in html
    assert 'id="query-error" class="query-error" role="alert" style="display:block"' in html
    assert 'id="query-results" class="logs-results" style="display:none"' in html


def test_bad_syntax_shows_server_text_in_page(client):
    html = client.get("/logs", params={"q": "AuthEvents | where | take 5"}).text
    assert "KQL parse error at position 19: unexpected token &#39;|&#39;" in html


def test_fetch_error_paths_are_distinguished_in_source():
    """Network failures and JS bugs must not share the 'Network error' label."""
    src = (Path(__file__).resolve().parents[1] / "siempl/web/templates/logs.html").read_text(encoding="utf-8")
    run_body = src[src.index("async function runQuery()"):src.index("function renderTable(")]
    assert run_body.count("showError('Network error'") == 1
    assert "catch (e) {\n    console.error(e);\n    showError('Client error'" in run_body
    assert "parseJsonText(text)" in run_body and "responseErrorMessage(" in run_body


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_served_inline_scripts_pass_node_check(client):
    html = client.get("/logs").text
    blocks = re.findall(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", html, re.S)
    js_blocks = [body for attrs, body in blocks if "json" not in attrs and "src=" not in attrs and body.strip()]
    assert len(js_blocks) >= 3  # helpers, controller, and base.html's inline script
    with tempfile.TemporaryDirectory(prefix="siempl_nodecheck_") as td:
        for i, body in enumerate(js_blocks):
            path = Path(td) / f"block{i}.js"
            path.write_text(body, encoding="utf-8")
            proc = subprocess.run([NODE, "--check", str(path)], capture_output=True, text=True,
                                  timeout=30, check=False)
            assert proc.returncode == 0, f"block {i}: {proc.stderr}"
