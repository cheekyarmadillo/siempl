"""Rules import: preview/commit for Sigma, Sentinel and KQL; URL allow-list; size cap; audit.

No network: the URL fetcher (`routes_rules.fetch_url_text`) is monkeypatched, and the
HTTP-level cap test replaces httpx.stream with a fake.

Run: SIEMPL_HOME=$(mktemp -d) .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_web_rules_import.py
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from siempl.db import Database
from siempl.web import routes_rules

SIGMA_OK = """\
title: Import Test Certutil Download
description: Certutil used to download a file.
level: high
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains: '-urlcache'
  condition: sel
tags:
  - attack.t1105
"""

SIGMA_UNSUPPORTED = """\
title: Import Test Unsupported
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\x.exe'
  condition: sel and not (1 of nothing_*)
"""

SENTINEL_NO_QUERY = """\
id: 2141523d-e043-4192-b5cf-8a080929c11c
name: Stub rule moved
description: |
  As part of content migration, this file is moved to a new location.
version: 1.1.2
"""

SENTINEL_OK = """\
id: 11111111-2222-3333-4444-555555555555
name: Import Test Sentinel Logon
description: Test sentinel rule.
severity: Medium
tactics:
  - Discovery
relevantTechniques:
  - T1087
query: |
  SecurityEvent
  | where EventID == 4625
"""

KQL_OK = "AuthEvents | where EventAction == \"login\" | take 5"
KQL_BAD = "AuthEvents | where ((("


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(prefix="siempl_web_import_") as td:
        os.environ["SIEMPL_HOME"] = str(td)
        db = Database(str(Path(td) / "t.duckdb"))
        yield db
        db.close()


@pytest.fixture
def client(db):
    from siempl.web import create_app
    return TestClient(create_app(db))


def audit_rows(db, action="rule.import"):
    return db.query("SELECT * FROM SiemplAudit WHERE EventCode = ? ORDER BY TimeGenerated", [action])


def audit_detail(row):
    """details dict of an audit row (stored in RawEvent; Extra is double-wrapped by insert_events)."""
    return json.loads(row["RawEvent"])["details"]


def rule_count(db):
    return db.query_one("SELECT count(*) AS c FROM rules")["c"]


# ----------------------------------------------------------------- preview
class TestPreview:
    def test_sigma_preview_ok_creates_nothing(self, client, db):
        r = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "yaml": SIGMA_OK, "preview": True})
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] and d["convertible"] is True and d["reason"] is None
        assert d["rule"]["name"] == "Import Test Certutil Download"
        assert d["rule"]["severity"] == "high"
        assert d["rule"]["tables"] == ["ProcessEvents"] or d["rule"]["tables"]
        assert "certutil" in d["rule"]["query"].lower()
        assert d["duplicate"] is None
        assert rule_count(db) == 0
        assert audit_rows(db) == []

    def test_sigma_preview_unsupported_has_reason(self, client, db):
        r = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "yaml": SIGMA_UNSUPPORTED, "preview": True})
        assert r.status_code == 200
        d = r.json()
        assert d["convertible"] is False
        assert d["rule"] is None
        assert isinstance(d["reason"], str) and len(d["reason"]) > 5
        assert rule_count(db) == 0

    def test_sigma_preview_warns_without_description(self, client):
        yaml = SIGMA_OK.replace("description: Certutil used to download a file.\n", "")
        d = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "yaml": yaml}).json()
        assert d["convertible"] is True
        assert any("description" in w.lower() for w in d["warnings"])

    def test_sentinel_preview_ok(self, client, db):
        d = client.post("/api/rules/import-preview",
                        json={"format": "sentinel", "yaml": SENTINEL_OK}).json()
        assert d["convertible"] is True
        assert d["rule"]["name"] == "Import Test Sentinel Logon"
        assert d["rule"]["tables"]
        assert any("verify" in w.lower() for w in d["warnings"])
        assert rule_count(db) == 0

    def test_sentinel_preview_no_query_reason_is_clear(self, client):
        d = client.post("/api/rules/import-preview",
                        json={"format": "sentinel", "yaml": SENTINEL_NO_QUERY}).json()
        assert d["convertible"] is False
        assert "no 'query' field" in d["reason"]

    def test_kql_preview_ok(self, client, db):
        d = client.post("/api/rules/import-preview",
                        json={"format": "kql", "yaml": KQL_OK, "name": "Manual KQL"}).json()
        assert d["convertible"] is True
        assert d["rule"]["name"] == "Manual KQL"
        assert d["rule"]["query_lang"] == "kql"
        assert d["rule"]["query"] == KQL_OK
        assert rule_count(db) == 0

    def test_kql_preview_bad_query_unsupported(self, client):
        d = client.post("/api/rules/import-preview",
                        json={"format": "kql", "yaml": KQL_BAD}).json()
        assert d["convertible"] is False
        assert "does not compile" in d["reason"]

    def test_unknown_format_rejected(self, client):
        r = client.post("/api/rules/import-preview", json={"format": "splunk", "yaml": "x"})
        assert r.status_code == 400
        assert "Unknown format" in r.json()["error"]

    def test_empty_input_rejected(self, client):
        r = client.post("/api/rules/import-preview", json={"format": "sigma", "yaml": "   "})
        assert r.status_code == 400


# ----------------------------------------------------------------- commit
class TestCommit:
    def test_import_creates_disabled_rule_and_audit_row(self, client, db):
        r = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "yaml": SIGMA_OK, "preview": False})
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["ok"] and d["enabled"] is False
        row = db.query_one("SELECT * FROM rules WHERE rule_id=?", [d["rule_id"]])
        assert row["enabled"] is False or row["enabled"] == False  # noqa: E712
        assert row["origin"] == "sigma"
        assert row["source_ref"].startswith("paste:")
        assert row["source_content"] == SIGMA_OK
        rows = audit_rows(db)
        assert len(rows) == 1
        assert rows[0]["ActorType"] == "user" and rows[0]["Actor"] == "user:web"
        assert rows[0]["TargetId"] == d["rule_id"]
        details = audit_detail(rows[0])
        assert details["format"] == "sigma" and details["result"] == "created"
        assert rows[0]["Outcome"] == "ok"

    def test_import_ignores_enabled_true_request(self, client, db):
        # All imports land disabled, even if the caller asks for enabled.
        r = client.post("/api/rules/import-sigma",
                        json={"yaml": SIGMA_OK, "mode": "import", "enabled": True})
        assert r.status_code == 200
        rid = r.json()["rule_id"]
        assert db.query_one("SELECT enabled FROM rules WHERE rule_id=?", [rid])["enabled"] in (False,)

    def test_duplicate_import_rejected_cleanly(self, client, db):
        first = client.post("/api/rules/import-preview",
                            json={"format": "sigma", "yaml": SIGMA_OK, "preview": False})
        assert first.status_code == 200
        second = client.post("/api/rules/import-preview",
                             json={"format": "sigma", "yaml": SIGMA_OK, "preview": False})
        assert second.status_code == 409
        d = second.json()
        assert d["ok"] is False
        assert d["duplicate_of"]["rule_id"] == first.json()["rule_id"]
        assert rule_count(db) == 1
        results = [audit_detail(r)["result"] for r in audit_rows(db)]
        assert results == ["created", "duplicate"]

    def test_duplicate_by_name_different_text_rejected(self, client, db):
        client.post("/api/rules/import-sentinel", json={"yaml": SENTINEL_OK, "preview": False})
        r = client.post("/api/rules/import-sentinel",
                        json={"yaml": SENTINEL_OK + "# edited\n", "preview": False})
        assert r.status_code == 409
        assert rule_count(db) == 1

    def test_preview_flags_duplicate_and_blocks(self, client):
        client.post("/api/rules/import-preview",
                    json={"format": "sigma", "yaml": SIGMA_OK, "preview": False})
        d = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "yaml": SIGMA_OK}).json()
        assert d["convertible"] is True
        assert d["duplicate"] is not None

    def test_unsupported_commit_is_422_and_audited(self, client, db):
        r = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "yaml": SIGMA_UNSUPPORTED, "preview": False})
        assert r.status_code == 422
        assert r.json()["reason"]
        assert rule_count(db) == 0
        assert audit_detail(audit_rows(db)[-1])["result"] == "unsupported"

    def test_sentinel_import_route(self, client, db):
        r = client.post("/api/rules/import-sentinel", json={"yaml": SENTINEL_OK, "preview": False})
        assert r.status_code == 200
        rid = r.json()["rule_id"]
        row = db.query_one("SELECT origin, enabled FROM rules WHERE rule_id=?", [rid])
        assert row["origin"] == "sentinel" and not row["enabled"]
        assert audit_detail(audit_rows(db)[-1])["format"] == "sentinel"

    def test_sentinel_route_defaults_to_preview(self, client, db):
        r = client.post("/api/rules/import-sentinel", json={"yaml": SENTINEL_OK})
        assert r.status_code == 200 and r.json()["convertible"] is True
        assert rule_count(db) == 0

    def test_kql_import_is_manual_origin_disabled(self, client, db):
        r = client.post("/api/rules/import-preview",
                        json={"format": "kql", "yaml": KQL_OK, "name": "Hand KQL", "preview": False})
        assert r.status_code == 200
        row = db.query_one("SELECT origin, enabled FROM rules WHERE name='Hand KQL'")
        assert row["origin"] == "manual" and not row["enabled"]


# ----------------------------------------------------------------- import-sigma compatibility
class TestImportSigmaCompat:
    def test_preview_shape_unchanged(self, client):
        r = client.post("/api/rules/import-sigma", json={"yaml": SIGMA_OK, "mode": "preview"})
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True and d["preview"]["name"] == "Import Test Certutil Download"
        assert d["preview"]["origin"] == "sigma"

    def test_preview_unsupported_is_400_with_error(self, client):
        r = client.post("/api/rules/import-sigma", json={"yaml": SIGMA_UNSUPPORTED, "mode": "preview"})
        assert r.status_code == 400
        assert r.json()["ok"] is False and r.json()["error"]

    def test_import_shape_unchanged(self, client, db):
        r = client.post("/api/rules/import-sigma", json={"yaml": SIGMA_OK, "mode": "import"})
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True and d["rule_id"].startswith("rule_")
        assert rule_count(db) == 1

    def test_empty_yaml_400(self, client):
        r = client.post("/api/rules/import-sigma", json={"yaml": "", "mode": "preview"})
        assert r.status_code == 400

    def test_import_unsupported_is_400(self, client):
        r = client.post("/api/rules/import-sigma", json={"yaml": SIGMA_UNSUPPORTED, "mode": "import"})
        assert r.status_code == 400
        assert r.json()["ok"] is False


# ----------------------------------------------------------------- URL import
class TestUrlImport:
    @pytest.mark.parametrize("url", [
        "http://raw.githubusercontent.com/o/r/main/rule.yml",          # not https
        "https://evil.example.com/o/r/main/rule.yml",                   # host not allowed
        "https://github.com.evil.example/o/r/main/rule.yml",            # lookalike host
        "https://user:pw@raw.githubusercontent.com/o/r/main/rule.yml",  # credentials
        "https://raw.githubusercontent.com/o/r/main/rule.exe",          # not yaml
        "https://github.com/o/r/tree/main/rules",                       # not a file view
    ])
    def test_bad_url_rejected_before_fetch(self, client, db, monkeypatch, url):
        called = []
        monkeypatch.setattr(routes_rules, "fetch_url_text", lambda u: called.append(u) or SIGMA_OK)
        r = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "url": url, "preview": False})
        assert r.status_code == 400, r.text
        assert r.json()["ok"] is False
        assert called == []
        assert rule_count(db) == 0
        assert audit_detail(audit_rows(db)[-1])["result"] == "invalid_url"

    def test_host_error_message_names_host(self):
        with pytest.raises(routes_rules.ImportInputError, match="evil.example.com"):
            routes_rules.normalize_import_url("https://evil.example.com/x/y/z.yml")

    def test_github_blob_rewritten_to_raw(self):
        assert routes_rules.normalize_import_url(
            "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/a.yaml"
        ) == "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Detections/a.yaml"

    def test_good_url_fetched_and_imported_disabled(self, client, db, monkeypatch):
        seen = []

        def fake(url):
            seen.append(url)
            return SIGMA_OK
        monkeypatch.setattr(routes_rules, "fetch_url_text", fake)
        url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/x/cert.yml"
        r = client.post("/api/rules/import-preview", json={"format": "sigma", "url": url, "preview": False})
        assert r.status_code == 200, r.text
        assert seen == [url]
        row = db.query_one("SELECT enabled, source_ref FROM rules WHERE rule_id=?", [r.json()["rule_id"]])
        assert not row["enabled"] and row["source_ref"] == url

    def test_fetch_failure_is_clean_400(self, client, db, monkeypatch):
        def boom(url):
            raise routes_rules.ImportInputError("Fetch failed: HTTP 404 (redirects are not followed)")
        monkeypatch.setattr(routes_rules, "fetch_url_text", boom)
        r = client.post("/api/rules/import-preview",
                        json={"format": "sigma", "url": "https://raw.githubusercontent.com/o/r/m/x.yml"})
        assert r.status_code == 400 and "404" in r.json()["error"]

    def test_size_cap_on_fetched_body(self, monkeypatch):
        """_http_get_capped refuses bodies over the cap, without buffering them all."""
        class FakeResp:
            status_code = 200
            headers = {}

            def iter_bytes(self):
                for _ in range(10):
                    yield b"x" * 200_000   # 2 MB total, cap is 1 MB
        class FakeCM:
            def __enter__(self): return FakeResp()
            def __exit__(self, *a): return False
        import httpx
        monkeypatch.setattr(httpx, "stream", lambda *a, **k: FakeCM())
        with pytest.raises(routes_rules.ImportInputError, match="larger than"):
            routes_rules._http_get_capped("https://raw.githubusercontent.com/o/r/m/x.yml")

    def test_size_cap_content_length_header(self, monkeypatch):
        class FakeResp:
            status_code = 200
            headers = {"content-length": str(5 * 1024 * 1024)}
            def iter_bytes(self):
                yield b"small"
        class FakeCM:
            def __enter__(self): return FakeResp()
            def __exit__(self, *a): return False
        import httpx
        monkeypatch.setattr(httpx, "stream", lambda *a, **k: FakeCM())
        with pytest.raises(routes_rules.ImportInputError, match="larger than"):
            routes_rules._http_get_capped("https://raw.githubusercontent.com/o/r/m/x.yml")

    def test_redirect_or_http_error_not_followed(self, monkeypatch):
        class FakeResp:
            status_code = 302
            headers = {}
        class FakeCM:
            def __enter__(self): return FakeResp()
            def __exit__(self, *a): return False
        import httpx
        monkeypatch.setattr(httpx, "stream", lambda *a, **k: FakeCM())
        with pytest.raises(routes_rules.ImportInputError, match="HTTP 302"):
            routes_rules._http_get_capped("https://raw.githubusercontent.com/o/r/m/x.yml")

    def test_paste_over_cap_rejected(self, client):
        big = "# " + "x" * (routes_rules.IMPORT_MAX_BYTES + 10)
        r = client.post("/api/rules/import-preview", json={"format": "kql", "yaml": big})
        assert r.status_code == 413


# ----------------------------------------------------------------- pages
class TestPages:
    def test_rules_page_has_single_import_dialog_and_no_format_origin_columns(self, client, db):
        client.post("/api/rules/import-sigma", json={"yaml": SIGMA_OK, "mode": "import"})
        client.post("/api/rules/import-sentinel", json={"yaml": SENTINEL_OK, "preview": False})
        client.post("/api/rules/import-preview", json={"format": "kql", "yaml": KQL_OK,
                                                        "name": "Hand KQL", "preview": False})
        html = client.get("/rules").text
        assert html.count('id="import-dlg"') == 1
        assert "<th>Format</th>" not in html and "<th>Origin</th>" not in html
        assert "Microsoft Sentinel YAML" in html and "KQL / plain query" in html
        assert "Import (disabled)" in html

    def test_imported_disabled_filter(self, client, db):
        client.post("/api/rules/import-sigma", json={"yaml": SIGMA_OK, "mode": "import"})
        client.post("/api/rules/import-preview", json={"format": "kql", "yaml": KQL_OK,
                                                        "name": "Hand KQL", "preview": False})
        html = client.get("/rules?imported=disabled").text
        assert "Import Test Certutil Download" in html
        assert "Hand KQL" not in html

    def test_rule_detail_shows_source_and_query(self, client, db):
        rid = client.post("/api/rules/import-sigma", json={"yaml": SIGMA_OK, "mode": "import"}).json()["rule_id"]
        html = client.get(f"/rules/{rid}").text
        assert "Original source" in html
        assert "Executable query" in html
        assert "-urlcache" in html  # from source_content, escaped

    def test_rule_form_has_no_separate_sigma_import(self, client):
        html = client.get("/rules/new/edit").text
        assert "previewSigma" not in html and "importSigma" not in html
        assert "/rules?import=1" in html
