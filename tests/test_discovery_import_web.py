"""import_web must go through the real importer (fetch_sigma) with an injectable client,
and surface fetch errors instead of silently reporting '0 imported'."""
from datetime import timedelta

from siempl.agents.discovery import RuleDiscoveryAgent, _fetch_and_import_rules
from siempl.db import Database, utcnow

SIGMA = """title: Test Cmd Whoami
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\\whoami.exe'
  condition: sel
level: medium
"""


def _db_with_process_events(tmp_path):
    db = Database(str(tmp_path / "t.duckdb"))
    db.insert_events("ProcessEvents", [{"TimeGenerated": utcnow() - timedelta(minutes=1), "SourceId": "s",
                                        "ProcessName": "whoami.exe", "HostName": "h"}])
    return db


def test_import_web_uses_fetch_sigma(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEMPL_HOME", str(tmp_path))
    db = _db_with_process_events(tmp_path)
    seen = []

    def client(url):
        seen.append(url)
        if url.startswith("https://api.github.com"):
            return [{"name": "whoami.yml", "download_url": "https://raw.example/whoami.yml"}]
        return {"content": SIGMA}

    res = _fetch_and_import_rules(db, RuleDiscoveryAgent(db), http_client=client)
    assert any("process_creation" in u for u in seen), seen
    assert res["errors"] == []
    assert res["fetched"]["process_creation"] >= 0
    assert res.get("proposed", 0) + res["imported"] + res["skipped"] >= 1   # default agent is dry-run: proposed, not written


def test_import_web_reports_fetch_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEMPL_HOME", str(tmp_path))
    db = _db_with_process_events(tmp_path)

    def client(url):
        raise RuntimeError("network down")

    res = _fetch_and_import_rules(db, RuleDiscoveryAgent(db), http_client=client)
    assert res["errors"] and "network down" in res["errors"][0]["error"]
