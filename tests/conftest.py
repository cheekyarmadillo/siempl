"""Test safety: the pytest suite must never spend real money.

The real OpenRouter key now lives at ~/.config/siempl/openrouter.key. Any test that enables AI
without injecting a fake transport would otherwise make a live HTTP call. We replace the real
transport with one that raises. Live tests must opt in with SIEMPL_LIVE_TEST=1 (the lifetime budget cap).
"""
import os

import pytest


def _blocked(url, headers, payload):
    raise RuntimeError("live LLM call blocked in tests; inject a fake transport (or SIEMPL_LIVE_TEST=1)")


@pytest.fixture(autouse=True)
def _no_live_llm(monkeypatch):
    if os.environ.get("SIEMPL_LIVE_TEST") != "1":
        import siempl.ai.llm as llm
        monkeypatch.setattr(llm, "_http_transport", _blocked)
    yield
