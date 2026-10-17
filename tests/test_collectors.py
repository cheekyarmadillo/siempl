"""Tests for collectors: syslog, HTTP ingest, file tailer, and CollectorManager.

Uses real localhost sockets on dynamically assigned free ports.
Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_collectors.py -q -v
"""
import asyncio
import json
import os
import socket
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from siempl.collectors import CollectorManager, FileTailer, SyslogServer, make_ingest_router
from siempl.db import Database
from siempl.web import create_app

# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "t.duckdb"))
    os.environ["SIEMPL_HOME"] = str(tmp_path)
    yield d
    d.close()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ── SyslogServer ────────────────────────────────────────────────────────────

class TestSyslogServer:
    """Integration test: start SyslogServer, send a UDP message, verify ingest."""

    @pytest.mark.asyncio
    async def test_udp_send_receive(self, db):
        port = _free_port()
        server = SyslogServer(db, source_id="src_udp", udp_port=port, tcp_port=port)
        try:
            await server.start()
            await asyncio.sleep(0.3)

            msg = b'<13>Oct 11 10:00:00 testhost testapp: UDP test message'
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg, ("127.0.0.1", port))
            sock.close()

            await asyncio.sleep(0.5)
            await server.stop()

            rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["src_udp"])
            assert len(rows) >= 1
            assert any("UDP test message" in (r.get("Message") or "") for r in rows)
        finally:
            if server._running:
                await server.stop()

    @pytest.mark.asyncio
    async def test_tcp_newline_framing(self, db):
        port = _free_port()
        server = SyslogServer(db, source_id="src_tcp_nl", udp_port=port, tcp_port=port)
        try:
            await server.start()
            await asyncio.sleep(0.3)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b'<13>Oct 11 10:00:00 host app: TCP newline test\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            await asyncio.sleep(0.5)
            await server.stop()

            rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["src_tcp_nl"])
            assert any("TCP newline test" in (r.get("Message") or "") for r in rows)
        finally:
            if server._running:
                await server.stop()

    @pytest.mark.asyncio
    async def test_tcp_octet_counting(self, db):
        port = _free_port()
        server = SyslogServer(db, source_id="src_tcp_oc", udp_port=port, tcp_port=port)
        try:
            await server.start()
            await asyncio.sleep(0.3)

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            msg = b"<13>Oct 11 10:00:00 host app: octet counting test"
            framed = str(len(msg)).encode() + b" " + msg
            writer.write(framed)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

            await asyncio.sleep(0.5)
            await server.stop()

            rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["src_tcp_oc"])
            assert any("octet counting test" in (r.get("Message") or "") for r in rows)
        finally:
            if server._running:
                await server.stop()

    @pytest.mark.asyncio
    async def test_port_in_use_errors_surfaced(self, db):
        """Starting on a used port sets last_error, does not crash."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        # Occupy the UDP port manually
        occupant = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        occupant.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupant.bind(("127.0.0.1", port))
        try:
            server = SyslogServer(db, source_id="src_fail", udp_port=port, tcp_port=port)
            await server.start()
            assert server.last_error is not None
            await server.stop()
        finally:
            occupant.close()

    @pytest.mark.asyncio
    async def test_source_id_tagged(self, db):
        """Events must be tagged with the source_id."""
        port = _free_port()
        server = SyslogServer(db, source_id="my_custom_source", udp_port=port, tcp_port=port)
        try:
            await server.start()
            await asyncio.sleep(0.3)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'<13>Oct 11 10:00:00 h a: tagged msg', ("127.0.0.1", port))
            sock.close()

            await asyncio.sleep(0.5)
            await server.stop()

            rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["my_custom_source"])
            assert len(rows) >= 1
        finally:
            if server._running:
                await server.stop()


# ── HTTP ingest router ───────────────────────────────────────────────────────

class TestHttpIngest:
    @pytest.fixture
    def router(self, db):
        return make_ingest_router(db)

    def test_router_is_fastapi_router(self, router):
        from fastapi import APIRouter
        assert isinstance(router, APIRouter)

    @pytest.mark.asyncio
    async def test_post_single_json(self, db, router):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post("/api/ingest/test-http", json={"message": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["received"] == 1
        assert data["inserted"] == 1
        rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["test-http"])
        assert len(rows) == 1

    @pytest.mark.asyncio
    async def test_post_json_array(self, db, router):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post("/api/ingest/test-http-array",
                           json=[{"msg": "a"}, {"msg": "b"}, {"msg": "c"}])
        assert resp.status_code == 200
        data = resp.json()
        assert data["received"] == 3
        assert data["inserted"] == 3

    @pytest.mark.asyncio
    async def test_post_ndjson(self, db, router):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        ndjson = '{"a":1}\n{"b":2}\n{"c":3}\n'
        resp = client.post("/api/ingest/test-ndjson", content=ndjson,
                          headers={"Content-Type": "application/json"})
        assert resp.status_code == 200
        assert resp.json()["inserted"] == 3

    @pytest.mark.asyncio
    async def test_post_with_parser_param(self, db, router):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post("/api/ingest/test-parser-override2?parser=windows_json",
                          json={"EventID": 4625, "event_data": {"TargetUserName": "bob"}})
        assert resp.status_code == 200
        assert resp.json()["inserted"] == 1

    @pytest.mark.asyncio
    async def test_post_invalid_body(self, db, router):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        resp = client.post("/api/ingest/test-bad", content="not json at all",
                          headers={"Content-Type": "application/json"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_post_unknown_source_created(self, db, router):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        client.post("/api/ingest/auto-create-http", json={"x": 1})
        src = db.query_one("SELECT status FROM sources WHERE source_id=?", ["auto-create-http"])
        assert src["status"] == "pending"


# ── FileTailer ───────────────────────────────────────────────────────────────

class TestFileTailer:
    def test_tail_new_file(self, db):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("line 1\nline 2\nline 3\n")
            fpath = f.name
        try:
            db.execute(
                "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
                ["file-src", "file", "active", json.dumps({"path": fpath})])
            tailer = FileTailer(db, "file-src", fpath)
            tailer.start()
            time.sleep(1.5)
            tailer.stop()
            tailer.join(timeout=3)
            rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["file-src"])
            assert len(rows) >= 3
        finally:
            os.unlink(fpath)

    def test_tail_appended_lines(self, db):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("initial line\n")
            fpath = f.name
        try:
            db.execute(
                "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
                ["file-src2", "file", "active", json.dumps({"path": fpath})])
            tailer = FileTailer(db, "file-src2", fpath)
            tailer.start()
            time.sleep(1)
            with open(fpath, "a") as f:
                f.write("appended line\n")
            time.sleep(1.5)
            tailer.stop()
            tailer.join(timeout=3)
            rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["file-src2"])
            assert len(rows) >= 2
        finally:
            os.unlink(fpath)

    def test_file_tailer_persists_offset(self, db):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("msg1\n")
            fpath = f.name
        try:
            db.execute(
                "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
                ["file-src3", "file", "active", json.dumps({"path": fpath})])
            tailer = FileTailer(db, "file-src3", fpath)
            tailer.start()
            time.sleep(1)
            tailer.stop()
            tailer.join(timeout=3)
            src = db.query_one("SELECT config FROM sources WHERE source_id=?", ["file-src3"])
            config = json.loads(src["config"]) if isinstance(src["config"], str) else src["config"]
            assert config.get("offset", 0) > 0
        finally:
            os.unlink(fpath)


# ── CollectorManager (TestClient integration) ──────────────────────────────

class TestCollectorManager:
    def test_start_stop_file_via_api(self, db):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("test\n")
            fpath = f.name
        try:
            db.execute(
                "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
                ["cm_file", "file", "active", json.dumps({"path": fpath})])
            cm = CollectorManager(db)
            result = cm.start("cm_file")
            assert result["ok"] is True
            assert result["running"] is True

            # FileTailer flushes on stop or on interval (5s); wait for it
            time.sleep(3.0)
            # Send the stop signal and wait for the tailer thread to join and flush
            stop = cm.stop("cm_file")
            assert stop["ok"] is True
            assert stop["running"] is False

            rows = db.query('SELECT * FROM "GenericEvents" WHERE SourceId=?', ["cm_file"])
            assert len(rows) >= 1
        finally:
            os.unlink(fpath)

    def test_start_stop_syslog_via_api(self, db):
        """Test full start -> send UDP -> verify Syslog row + events_total -> stop via CollectorManager."""
        port = _free_port()
        db.execute(
            "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
            ["cm_sys", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])
        cm = CollectorManager(db)
        result = cm.start("cm_sys")
        assert result["ok"] is True
        time.sleep(0.8)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b'<13>Oct 11 10:00:00 h a: collector manager test', ("127.0.0.1", port))
        sock.close()

        time.sleep(2.0)

        stop = cm.stop("cm_sys")
        assert stop["ok"] is True

        rows = db.query('SELECT * FROM "Syslog" WHERE SourceId=?', ["cm_sys"])
        assert len(rows) >= 1
        assert any("collector manager test" in (r.get("Message") or "") for r in rows)

        src = db.query_one("SELECT events_total FROM sources WHERE source_id=?", ["cm_sys"])
        assert src["events_total"] is not None and src["events_total"] > 0

    def test_status_endpoint(self, db):
        port = _free_port()
        db.execute(
            "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
            ["cm_stat", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])
        cm = CollectorManager(db)
        cm.start("cm_stat")
        time.sleep(0.3)
        stat = cm.status()
        assert "cm_stat" in stat
        assert stat["cm_stat"]["running"] is True
        assert "listening_ports" in stat["cm_stat"]
        cm.stop("cm_stat")

    def test_port_in_use_error(self, db):
        """Two syslog sources on the same port => second start returns error."""
        port = _free_port()
        db.execute(
            "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
            ["sys_a", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])
        db.execute(
            "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
            ["sys_b", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])

        cm = CollectorManager(db)
        r1 = cm.start("sys_a")
        assert r1["ok"] is True
        time.sleep(0.5)

        r2 = cm.start("sys_b")
        # OSError should be caught and surfaced
        assert r2["ok"] is False
        assert "last_error" in r2

        cm.stop("sys_a")

    def test_stop_all(self, db):
        port = _free_port()
        db.execute(
            "INSERT INTO sources(source_id, kind, status, config) VALUES (?,?,?,?)",
            ["sa_src", "syslog", "active", json.dumps({"udp_port": port, "tcp_port": port})])
        cm = CollectorManager(db)
        cm.start("sa_src")
        time.sleep(0.3)
        cm.stop_all()
        stat = cm.status()
        assert "sa_src" not in stat


# ── Token enforcement via TestClient ────────────────────────────────────────

class TestTokenEnforcement:
    @pytest.fixture
    def client(self, db):
        cm = CollectorManager(db)
        app = create_app(db, collector_manager=cm)
        return TestClient(app)

    def test_no_token_200(self, client, db):
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["tok_open", "http", "active", "{}"])
        r = client.post("/api/ingest/tok_open", json={"msg": "hello"})
        assert r.status_code == 200

    def test_bearer_required_401(self, client, db):
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["tok_sec", "http", "active", json.dumps({"token": "my-secret"})])
        r = client.post("/api/ingest/tok_sec", json={"msg": "hello"})
        assert r.status_code == 401
        r2 = client.post("/api/ingest/tok_sec", json={"msg": "hello"},
                         headers={"Authorization": "Bearer my-secret"})
        assert r2.status_code == 200

    def test_x_siempl_token(self, client, db):
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["tok_x", "http", "active", json.dumps({"token": "x-secret"})])
        r = client.post("/api/ingest/tok_x", json={"msg": "hello"},
                        headers={"X-Siempl-Token": "x-secret"})
        assert r.status_code == 200

    def test_paused_returns_409(self, client, db):
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["tok_pause", "http", "paused", json.dumps({"token": "tok"})])
        r = client.post("/api/ingest/tok_pause", json={"msg": "hello"},
                        headers={"Authorization": "Bearer tok"})
        assert r.status_code == 409


# ── Audit trail ─────────────────────────────────────────────────────────────

class TestAuditTrail:
    def test_start_stop_audited(self, db):
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["audit_src", "http", "active", "{}"])
        cm = CollectorManager(db)
        app = create_app(db, collector_manager=cm)
        client = TestClient(app)
        client.post("/api/sources/audit_src/start")
        client.post("/api/sources/audit_src/stop")
        rows = db.query('SELECT * FROM "SiemplAudit" WHERE TargetId=?', ["audit_src"])
        actions = {r["Action"] for r in rows}
        assert "source.start" in actions
        assert "source.stop" in actions

    def test_pause_resume_audited(self, db):
        db.execute(
            "INSERT INTO sources(source_id,kind,status,config) VALUES (?,?,?,?)",
            ["audit_pr", "http", "active", "{}"])
        cm = CollectorManager(db)
        app = create_app(db, collector_manager=cm)
        client = TestClient(app)
        client.post("/api/sources/audit_pr/pause")
        client.post("/api/sources/audit_pr/resume")
        rows = db.query('SELECT * FROM "SiemplAudit" WHERE TargetId=?', ["audit_pr"])
        actions = {r["Action"] for r in rows}
        assert "source.pause" in actions
        assert "source.resume" in actions
