"""Tests for sample data: idempotency, clear-only-samples, agent non-LLM paths.

Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest tests/test_sample_data.py -q -p no:cacheprovider
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_sample_") as td:
        os.environ["SIEMPL_HOME"] = td
        db = Database(str(Path(td) / "t.duckdb"))
        yield db
        db.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    app = create_app(db)
    return TestClient(app)


# ------------------------------------------------------------------
# Idempotency
# ------------------------------------------------------------------

class TestIdempotency:
    def test_load_twice_same_counts(self, db):
        from siempl.testdata.sample import load_samples
        s1 = load_samples(db, seed=42)
        s2 = load_samples(db, seed=42)
        assert s1["rules_added"] > 0
        assert s2["rules_added"] == 0
        assert s2["alerts_added"] == 0
        assert s2["incidents_added"] == 0
        assert s2["entities_added"] == 0
        assert s2["events_added"] == 0
        assert s2["table_usage_added"] == 0
        assert s2["recommendations_added"] == 0
        assert s2["sources_added"] == 0
        assert s2["filters_added"] == 0

    def test_entities_stable(self, db):
        from siempl.testdata.sample import load_samples
        load_samples(db, seed=42)
        e = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["ip:203.0.113.42"])
        assert e is not None
        assert e["watch"] is True
        assert e["notes"] == "sample"

    def test_rules_stable(self, db):
        from siempl.testdata.sample import load_samples
        load_samples(db, seed=42)
        r = db.query_one("SELECT * FROM rules WHERE rule_id=?", ["sample_brute_force"])
        assert r is not None
        assert r["enabled"] is True


# ------------------------------------------------------------------
# Clear
# ------------------------------------------------------------------

class TestClear:
    def test_clear_removes_only_samples(self, db):
        from siempl.testdata.sample import clear_samples, load_samples
        # Seed a non-sample entity
        db.execute(
            "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ["ip:1.2.3.4", "ip", "1.2.3.4", 50, 0, 1, "2025-01-01", "2025-01-01"])
        s1 = load_samples(db, seed=42)
        assert s1["entities_added"] > 0
        s2 = clear_samples(db)
        assert s2["entities_deleted"] == s1["entities_added"]
        # Non-sample entity should survive
        e = db.query_one("SELECT * FROM entities WHERE entity_id=?", ["ip:1.2.3.4"])
        assert e is not None

    def test_clear_then_load(self, db):
        from siempl.testdata.sample import clear_samples, load_samples
        load_samples(db, seed=42)
        clear_samples(db)
        s3 = load_samples(db, seed=42)
        assert s3["rules_added"] > 0


# ------------------------------------------------------------------
# Web routes
# ------------------------------------------------------------------

class TestWebRoutes:
    def test_samples_page_renders(self, client):
        r = client.get("/samples")
        assert r.status_code == 200
        assert "Load sample data" in r.text

    def test_api_load_samples(self, client, db):
        r = client.post("/api/testdata/samples", json={"seed": 42})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["summary"]["rules_added"] > 0

    def test_api_clear_samples(self, client, db):
        client.post("/api/testdata/samples", json={"seed": 42})
        r = client.post("/api/testdata/samples/clear")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True

    def test_load_is_idempotent_via_api(self, client, db):
        client.post("/api/testdata/samples", json={"seed": 42}).json()["summary"]
        s2 = client.post("/api/testdata/samples", json={"seed": 42}).json()["summary"]
        # After first load, second should add nothing
        assert s2["rules_added"] == 0
        assert s2["alerts_added"] == 0


# ------------------------------------------------------------------
# Agent non-LLM paths
# ------------------------------------------------------------------

class TestAgentPaths:
    def test_optimizer_runs_against_samples(self, db):
        from siempl.agents.optimizer import IngestionOptimizerAgent
        from siempl.testdata.sample import load_samples
        load_samples(db, seed=42)
        agent = IngestionOptimizerAgent(db)
        res = agent.run(input_ref="test_opt")
        assert res.status == "ok"
        assert "tables" in res.output

    def test_tuning_runs_against_samples(self, db):
        from siempl.agents.tuning import TuningAgent
        from siempl.testdata.sample import load_samples
        load_samples(db, seed=42)
        agent = TuningAgent(db)
        res = agent.run(input_ref="test_tune")
        assert res.status == "ok"
        assert res.output["total_rules_analyzed"] >= 1


# ------------------------------------------------------------------
# 20k entity benchmark (< 1s page render)
# ------------------------------------------------------------------

class TestPerf20k:
    def test_entities_list_20k_under_1s(self, client, db):
        """Seed 20k entities and verify list page renders fast."""
        from datetime import datetime
        now = datetime.now(UTC).replace(tzinfo=None)
        # Bulk insert 20k entities
        batch = []
        for i in range(20000):
            val = f"10.0.{i // 256}.{i % 256}"
            eid = f"ip:{val}"
            batch.append([eid, "ip", val, 50, 0, 1, now, now])
            if len(batch) >= 1000:
                db.execute(
                    "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) "
                    "VALUES " + ",".join(["(?,?,?,?,?,?,?,?)"] * len(batch)),
                    [x for row in batch for x in row])
                batch = []
        if batch:
            db.execute(
                "INSERT INTO entities(entity_id,type,value,reputation,alert_count,event_count,first_seen,last_seen) "
                "VALUES " + ",".join(["(?,?,?,?,?,?,?,?)"] * len(batch)),
                [x for row in batch for x in row])

        import time
        t0 = time.monotonic()
        r = client.get("/entities")
        elapsed = time.monotonic() - t0
        assert r.status_code == 200
        assert elapsed < 1.0, f"Entities list took {elapsed:.2f}s (target <1s)"
