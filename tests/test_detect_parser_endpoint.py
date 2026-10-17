"""POST /api/sources/detect-parser must actually try the registered parsers.

Bug (present since before the 2026-10-13 refactor, confirmed against the pre-refactor code): the handler called
parser.parse(...), but parsers are plain callables, so every attempt raised AttributeError, was swallowed at
debug level, and the endpoint always answered candidates=[].
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from siempl.collectors import CollectorManager
from siempl.db import Database
from siempl.web import create_app

CEF = "CEF:0|Vendor|Prod|1.0|100|Test event|5|src=10.0.0.1 dst=10.0.0.2 suser=bob"


@pytest.fixture
def client(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    os.environ["SIEMPL_HOME"] = str(tmp_path)
    yield TestClient(create_app(db, collector_manager=CollectorManager(db)))
    db.close()


def test_detect_parser_finds_cef(client):
    r = client.post("/api/sources/detect-parser", json={"samples": [CEF]})
    assert r.status_code == 200
    cands = r.json()["candidates"]
    assert cands, "no candidates for a valid CEF line"
    assert "cef" in [c["parser"] for c in cands]
    cef = next(c for c in cands if c["parser"] == "cef")
    assert cef["parsed_count"] == 1
    assert cef["fields"]


def test_detect_parser_empty_samples_is_400(client):
    r = client.post("/api/sources/detect-parser", json={"samples": []})
    assert r.status_code == 400


# Every parser is lenient (returns a fallback event for any line), so ranking has to come from how much
# real data a parser extracted, not from registration order.
SAMPLES = {
    "cef": CEF,
    "syslog_rfc3164": "<34>Oct 13 10:00:00 host sshd[123]: Failed password for root from 10.0.0.5 port 22 ssh2",
    "syslog_rfc5424": "<34>1 2026-10-13T10:00:00Z host app 1234 ID47 - Failed password for root from 10.0.0.5",
    "apache_combined": '10.0.0.1 - - [13/Oct/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8"',
    "windows_json": ('{"EventID":4625,"Channel":"Security","Computer":"WS1",'
                     '"TimeCreated":"2026-10-13T10:00:00Z","EventData":{"TargetUserName":"bob","IpAddress":"1.2.3.4"}}'),
    "zeek_dns": ('{"ts":1760000000.0,"uid":"C1","id.orig_h":"1.2.3.4","id.resp_h":"8.8.8.8",'
                 '"query":"a.com","qtype_name":"A"}'),
}


@pytest.mark.parametrize("expected", sorted(SAMPLES))
def test_detect_parser_ranks_the_right_parser_first(client, expected):
    r = client.post("/api/sources/detect-parser", json={"samples": [SAMPLES[expected]]})
    assert r.status_code == 200
    assert r.json()["candidates"][0]["parser"] == expected


def test_detect_parser_cef_beats_lenient_syslog_despite_registration_order(client):
    from siempl.ingest.parsers import list_parsers
    order = list(list_parsers())
    assert order.index("syslog_rfc3164") < order.index("cef")  # the premise of the old bug
    r = client.post("/api/sources/detect-parser", json={"samples": [CEF]})
    assert r.json()["candidates"][0]["parser"] == "cef"


def test_detect_parsers_limit_and_shape():
    from siempl.ingest._detect import detect_parsers
    out = detect_parsers([CEF], limit=2)
    assert len(out) == 2
    assert set(out[0]) == {"parser", "tables", "fields", "parsed_count"}
