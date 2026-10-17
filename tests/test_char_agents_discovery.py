"""Characterization tests for agents functions with weak coverage.

Run BEFORE refactoring to lock current behavior.
"""

from datetime import UTC, datetime

from siempl.agents.discovery import _fetch_and_import_rules
from siempl.db import Database


def _utc_now():
    return datetime.now(UTC).replace(tzinfo=None)


class FakeHttpClient:
    """Minimal fake that satisfies the fetch_sigma injection path."""

    def __init__(self, rules):
        self.rules = rules

    def __call__(self, *a, **kw):
        return self.rules


class TestFetchAndImportRules:
    def test_imports_rule_when_query_has_few_hits(self, tmp_path, monkeypatch):
        db = Database(str(tmp_path / "t.duckdb"))
        from siempl.agents.discovery import RuleDiscoveryAgent
        agent = RuleDiscoveryAgent(db, dry_run=False)

        # Seed data so ProcessEvents has rows
        for i in range(200):
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now(), "SourceId": "src1",
                "SourceType": "test", "ProcessName": f"proc{i % 20}",
                "HostName": f"host{i % 10}", "Message": "test",
                "EventCode": "4688", "EventAction": "process_start",
                "EventResult": "success",
            }])

        fake_rule = {
            "name": "Fake Sigma Rule",
            "description": "test",
            "severity": "medium",
            "query": 'ProcessEvents | where ProcessName == "nonexistent"',
            "query_lang": "kql",
            "tables": ["ProcessEvents"],
            "source_ref": "sigma:test/fake.yml",
        }

        # Monkeypatch fetch_sigma inside the module to return our fake rule
        import siempl.detect.importer as importer
        original_fetch_sigma = importer.fetch_sigma
        importer.fetch_sigma = lambda **kw: [fake_rule]

        try:
            result = _fetch_and_import_rules(db, agent, http_client=object())
            # Should have imported 1 rule
            assert result["imported"] == 1
            assert result["imported_rules"][0]["name"] == "Fake Sigma Rule"
        finally:
            importer.fetch_sigma = original_fetch_sigma

    def test_skips_duplicate_source_ref(self, tmp_path, monkeypatch):
        db = Database(str(tmp_path / "t.duckdb"))
        from siempl.agents.discovery import RuleDiscoveryAgent
        agent = RuleDiscoveryAgent(db, dry_run=False)

        for i in range(200):
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now(), "SourceId": "src1",
                "SourceType": "test", "ProcessName": f"proc{i % 20}",
                "HostName": f"host{i % 10}", "Message": "test",
                "EventCode": "4688", "EventAction": "process_start",
                "EventResult": "success",
            }])

        fake_rule = {
            "name": "Dup Rule",
            "description": "test",
            "severity": "medium",
            "query": 'ProcessEvents | where ProcessName == "nonexistent"',
            "query_lang": "kql",
            "tables": ["ProcessEvents"],
            "source_ref": "sigma:test/dup.yml",
        }

        import siempl.detect.importer as importer
        original_fetch_sigma = importer.fetch_sigma
        importer.fetch_sigma = lambda **kw: [fake_rule]

        try:
            # First import
            r1 = _fetch_and_import_rules(db, agent, http_client=object())
            assert r1["imported"] == 1
            # Second import should skip as duplicate
            r2 = _fetch_and_import_rules(db, agent, http_client=object())
            assert r2["skipped"] >= 1
            assert any("duplicate" in sr["reason"] for sr in r2["skipped_rules"])
        finally:
            importer.fetch_sigma = original_fetch_sigma

    def test_dry_run_proposes_instead_of_imports(self, tmp_path, monkeypatch):
        db = Database(str(tmp_path / "t.duckdb"))
        from siempl.agents.discovery import RuleDiscoveryAgent
        agent = RuleDiscoveryAgent(db, dry_run=True)

        for i in range(200):
            db.insert_events("ProcessEvents", [{
                "TimeGenerated": _utc_now(), "SourceId": "src1",
                "SourceType": "test", "ProcessName": f"proc{i % 20}",
                "HostName": f"host{i % 10}", "Message": "test",
                "EventCode": "4688", "EventAction": "process_start",
                "EventResult": "success",
            }])

        fake_rule = {
            "name": "Dry Rule",
            "description": "test",
            "severity": "medium",
            "query": 'ProcessEvents | where ProcessName == "nonexistent"',
            "query_lang": "kql",
            "tables": ["ProcessEvents"],
            "source_ref": "sigma:test/dry.yml",
        }

        import siempl.detect.importer as importer
        original_fetch_sigma = importer.fetch_sigma
        importer.fetch_sigma = lambda **kw: [fake_rule]

        try:
            result = _fetch_and_import_rules(db, agent, http_client=object())
            assert result.get("proposed", 0) == 1
            assert result["imported"] == 0
        finally:
            importer.fetch_sigma = original_fetch_sigma
