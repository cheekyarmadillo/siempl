"""Settings: OpenRouter key entry. Key lives only in the key file; never leaks into HTML/JSON/DB."""
from __future__ import annotations

import stat

import pytest
from fastapi.testclient import TestClient

from siempl.ai.llm import AIBudgetExceeded, LLMClient
from siempl.db import Database
from siempl.web import create_app, routes_settings_key

KEY = "sk-or-v1-" + "a1b2c3d4e5f6" * 4
NEEDLE = KEY[:30]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    db = Database(tmp_path / "t.duckdb")
    db.init_schema()
    kf = tmp_path / "cfg" / "or.key"
    db.set_setting("openrouter_key_file", str(kf))
    return db, TestClient(create_app(db)), kf


def test_save_writes_0600_file_and_masks(env):
    db, c, kf = env
    r = c.post("/api/settings/key", json={"key": KEY})
    assert r.status_code == 200 and r.json()["ok"]
    assert kf.read_text().strip() == KEY
    assert stat.S_IMODE(kf.stat().st_mode) == 0o600
    assert stat.S_IMODE(kf.parent.stat().st_mode) == 0o700
    assert NEEDLE not in r.text and r.json()["label"].endswith(KEY[-4:] + ")")


def test_no_leak_in_html_status_db_or_audit(env):
    db, c, kf = env
    c.post("/api/settings/key", json={"key": KEY})
    for text in (c.get("/settings").text, c.get("/api/settings/key/status").text):
        assert NEEDLE not in text
    dump = str(db.query("SELECT * FROM settings")) + str(db.query('SELECT "RawEvent" FROM "SiemplAudit"'))
    assert NEEDLE not in dump


@pytest.mark.parametrize("bad", ["", "   ", "short", "has space " + "x" * 30, "line\nbreak" + "x" * 30, 123, None])
def test_rejects_bad_shapes(env, bad):
    db, c, kf = env
    r = c.post("/api/settings/key", json={"key": bad})
    assert r.status_code == 400 and not kf.exists()


def test_remove(env):
    db, c, kf = env
    c.post("/api/settings/key", json={"key": KEY})
    r = c.delete("/api/settings/key")
    assert r.json()["removed"] is True and not kf.exists()
    assert c.delete("/api/settings/key").json()["removed"] is False


def test_env_takes_precedence_and_is_not_revealed(env, monkeypatch):
    db, c, kf = env
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-ENVSECRET" + "z" * 20)
    st = c.get("/api/settings/key/status").json()
    assert st["source"] == "env" and "ENVSECRET" not in str(st)
    assert "ENVSECRET" not in c.get("/settings").text


def test_test_key_uses_injected_getter(env, monkeypatch):
    db, c, kf = env
    assert c.post("/api/settings/key/test").status_code == 400
    c.post("/api/settings/key", json={"key": KEY})
    seen = {}

    def ok(url, headers):
        seen["auth"] = headers["Authorization"]
        return 200, {"data": {"label": "SECRETLABEL", "usage": 1.5, "limit": 20, "limit_remaining": 18.5}}

    monkeypatch.setattr(routes_settings_key, "_getter", ok)
    r = c.post("/api/settings/key/test")
    assert r.json()["result"] == "valid" and "limit $20.00" in r.json()["message"]
    assert "SECRETLABEL" not in r.text and KEY in seen["auth"]
    monkeypatch.setattr(routes_settings_key, "_getter", lambda u, h: (401, {}))
    assert c.post("/api/settings/key/test").json()["result"] == "invalid"

    def boom(url, headers):
        raise OSError("down")

    monkeypatch.setattr(routes_settings_key, "_getter", boom)
    assert c.post("/api/settings/key/test").json()["result"] == "network_error"


def test_total_budget_default_is_10_and_enforced(env):
    db, c, kf = env
    assert float(db.get_setting("ai_total_usd_budget")) == 10.0
    db.execute("INSERT INTO ai_usage(agent,model,tokens_in,tokens_out,cost_usd) VALUES ('t','m',1,1,10.0)")
    db.set_setting("ai_daily_usd_cap", 100.0)
    with pytest.raises(AIBudgetExceeded):
        LLMClient(db)._check_budget()
