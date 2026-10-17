"""Tests for ingestion sources API: CRUD, start/stop, token enforcement, PUT validation."""
from __future__ import annotations

import json
import os
import socket
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from siempl.collectors import CollectorManager
from siempl.db import Database
from siempl.web import create_app

# ---- fixtures --------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    """Fresh database for each test."""
    d = Database(str(tmp_path / "t.duckdb"))
    os.environ["SIEMPL_HOME"] = str(tmp_path)
    yield d
    d.close()


@pytest.fixture
def client(db):
    """TestClient with CollectorManager attached."""
    cm = CollectorManager(db)
    app = create_app(db, collector_manager=cm)
    return TestClient(app)


# ---- CRUD + validation ------------------------------------------------------

def test_create_source(client, db):
    r = client.post("/api/sources", json={
        "source_id": "src_http",
        "name": "HTTP Test",
        "kind": "http",
        "config": {"token": "secret123"},
        "target_table": "GenericEvents"
    })
    assert r.status_code == 200
    assert r.json()["ok"] is True
    src = db.query_one("SELECT * FROM sources WHERE source_id=?", ["src_http"])
    assert src is not None
    assert src["kind"] == "http"


def test_create_source_validation_invalid_port(client):
    r = client.post("/api/sources", json={
        "source_id": "src_syslog",
        "name": "Bad Port",
        "kind": "syslog",
        "config": {"udp_port": 80, "tcp_port": 80}
    })
    assert r.status_code == 400
    data = r.json()
    assert "details" in data


def test_create_source_validation_nonexistent_file(client):
    r = client.post("/api/sources", json={
        "source_id": "src_file",
        "name": "Bad Path",
        "kind": "file",
        "config": {"path": "/nonexistent/file.log"}
    })
    assert r.status_code == 400
    assert "path" in r.json()["details"]


def test_put_source_validation_unknown_table(client, db):
    db.execute("INSERT INTO sources(source_id,kind,name,config) VALUES (?,?,?,?)",
               ["test_put", "http", "Test", "{}"])
    r = client.put("/api/sources/test_put", json={
        "target_table": "NoSuchTable",
        "name": "Updated"
    })
    assert r.status_code == 400
    assert r.json()["details"]["target_table"]


def test_put_source_validation_unknown_parser(client, db):
    db.execute("INSERT INTO sources(source_id,kind,name,config) VALUES (?,?,?,?)",
               ["test_put2", "http", "Test", "{}"])
    r = client.put("/api/sources/test_put2", json={
        "parser": "no_such_parser_xyz"
    })
    assert r.status_code == 400


# ---- start / stop / status --------------------------------------------------

def test_start_stop_file_collector(client, db):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("test line\n")
        fpath = f.name

    try:
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["file_src", "file", "active", json.dumps({"path": fpath})])

        # Start
        r = client.post("/api/sources/file_src/start")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["running"] is True

        time.sleep(1.2)

        # Stop
        r = client.post("/api/sources/file_src/stop")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["running"] is False

        # Verify events landed
        rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["file_src"])
        assert len(rows) >= 1
    finally:
        os.unlink(fpath)


def test_start_stop_syslog_collector(client, db):
    # Use a high random free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["syslog_src", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])

    # Start
    r = client.post("/api/sources/syslog_src/start")
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Give the async thread time to bind
    time.sleep(0.8)

    # Send a UDP syslog message
    msg = b'<13>Oct 11 10:00:00 testhost testapp: collector test message'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg, ("127.0.0.1", port))
    sock.close()

    time.sleep(2.0)

    # Stop
    r2 = client.post("/api/sources/syslog_src/stop")
    assert r2.status_code == 200
    assert r2.json()["ok"] is True

    # Verify events landed
    rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["syslog_src"])
    assert len(rows) >= 1
    assert any("collector test message" in (row.get("Message") or "") for row in rows)

    # Verify events_total bumped
    src = db.query_one("SELECT events_total FROM sources WHERE source_id=?", ["syslog_src"])
    assert src["events_total"] is not None and src["events_total"] > 0


def test_collectors_status_endpoint(client, db):
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["syslog_stat", "syslog", "active", json.dumps({"udp_port": 19999, "tcp_port": 19999})])
    r = client.get("/api/collectors/status")
    assert r.status_code == 200
    assert "collectors" in r.json()


def test_port_in_use_error(client, db):
    """Two syslog sources on the same port => second start gets last_error."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["syslog_a", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["syslog_b", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])

    # Start first (binds the port)
    r1 = client.post("/api/sources/syslog_a/start")
    assert r1.status_code == 200
    time.sleep(0.5)

    # Start second: should fail because port is already in use by syslog_a
    r2 = client.post("/api/sources/syslog_b/start")
    time.sleep(0.5)
    data = r2.json()
    assert data["ok"] is False
    assert "last_error" in data

    # Cleanup
    client.post("/api/sources/syslog_a/stop")


# ---- pause/resume/delete ----------------------------------------------------

def test_pause_stops_collector(client, db):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("line\n")
        fpath = f.name
    try:
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["file_pause", "file", "active", json.dumps({"path": fpath})])
        client.post("/api/sources/file_pause/start")
        time.sleep(0.3)
        r = client.post("/api/sources/file_pause/pause")
        assert r.status_code == 200

        s = db.query_one("SELECT status FROM sources WHERE source_id=?", ["file_pause"])
        assert s["status"] == "paused"
    finally:
        os.unlink(fpath)


def test_delete_stops_collector_first(client, db):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("line\n")
        fpath = f.name
    try:
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["file_del", "file", "active", json.dumps({"path": fpath})])
        client.post("/api/sources/file_del/start")
        time.sleep(0.3)
        r = client.post("/api/sources/file_del/delete")
        assert r.status_code == 200
        assert db.query_one("SELECT * FROM sources WHERE source_id=?", ["file_del"]) is None
    finally:
        os.unlink(fpath)


# ---- token enforcement ------------------------------------------------------

def test_http_ingest_no_token_required(client, db):
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["http_open", "http", "active", "{}"])
    r = client.post("/api/ingest/http_open", json={"msg": "hello"})
    assert r.status_code == 200
    assert r.json()["inserted"] == 1


def test_http_ingest_token_required_bearer(client, db):
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["http_sec", "http", "active", json.dumps({"token": "tok123"})])
    r = client.post("/api/ingest/http_sec", json={"msg": "hello"})
    assert r.status_code == 401

    r2 = client.post("/api/ingest/http_sec", json={"msg": "hello"},
                     headers={"Authorization": "Bearer tok123"})
    assert r2.status_code == 200
    assert r2.json()["inserted"] == 1


def test_http_ingest_token_required_x_siempl(client, db):
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["http_x", "http", "active", json.dumps({"token": "tok456"})])
    r = client.post("/api/ingest/http_x", json={"msg": "hello"},
                    headers={"X-Siempl-Token": "tok456"})
    assert r.status_code == 200
    assert r.json()["inserted"] == 1


def test_http_ingest_paused_returns_409(client, db):
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["http_pause", "http", "paused", json.dumps({"token": "tok"})])
    r = client.post("/api/ingest/http_pause", json={"msg": "hello"},
                    headers={"Authorization": "Bearer tok"})
    assert r.status_code == 409


# ---- audit ------------------------------------------------------------------

def test_start_stop_are_audited(client, db):
    db.execute(
        "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
        ["audit_src", "http", "active", "{}"])
    client.post("/api/sources/audit_src/start")
    client.post("/api/sources/audit_src/stop")
    rows = db.query('SELECT * FROM "SiemplAudit" WHERE TargetId=?', ["audit_src"])
    actions = {r["Action"] for r in rows}
    assert "source.start" in actions
    assert "source.stop" in actions


# ---- ingestion UI -----------------------------------------------------------

def test_ingestion_page_renders(client):
    r = client.get("/ingestion")
    assert r.status_code == 200
    assert "Ingestion" in r.text
    assert "Sources" in r.text
