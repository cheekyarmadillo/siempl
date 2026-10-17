"""The ONLY place an LLM may be called (OpenRouter chat completions).

SAFETY CONTRACT (no surprise AI bill):
  * Every call checks settings['ai_enabled'] (default False) -> AIDisabledError otherwise.
  * The API key is read lazily at call time from env OPENROUTER_API_KEY or the key file
    (settings['openrouter_key_file']). It is never stored in the DB, config, logs, or repo.
  * Daily USD/token caps are enforced BEFORE each call using the ai_usage table -> AIBudgetExceeded.
  * Tests MUST pass a fake `transport`; no test may touch the network. There is a unit test that
    asserts the default client raises AIDisabledError without any network I/O.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..db import Database

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


class AIDisabledError(RuntimeError):
    """ai_enabled is false (or no key). Callers must catch this and fall back to heuristics."""


class AIBudgetExceeded(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    tool_calls: list[dict] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def json(self) -> Any:
        t = self.text.strip()
        if t.startswith("```"):
            t = t.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(t)


# transport(url, headers, payload) -> dict (OpenRouter/OpenAI-style response). Injected in tests.
Transport = Callable[[str, dict, dict], dict]


def _http_transport(url: str, headers: dict, payload: dict) -> dict:
    import httpx  # imported lazily: disabled mode never touches httpx
    r = httpx.post(url, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()


class LLMClient:
    def __init__(self, db: Database, transport: Transport | None = None):
        self.db = db
        self.transport = transport or _http_transport

    # -- gate -----------------------------------------------------------------------
    def is_enabled(self) -> bool:
        return bool(self.db.get_setting("ai_enabled", False))

    def _key(self) -> str:
        k = os.environ.get("OPENROUTER_API_KEY")
        if not k:
            p = Path(os.path.expanduser(self.db.get_setting("openrouter_key_file", "")))
            if p.is_file():
                k = p.read_text().strip()
        if not k:
            raise AIDisabledError("ai_enabled but no OpenRouter key (env OPENROUTER_API_KEY or key file)")
        return k

    def usage_today(self) -> dict:
        r = self.db.query_one(
            "SELECT coalesce(sum(tokens_in+tokens_out),0) AS tokens, coalesce(sum(cost_usd),0) AS usd "
            "FROM ai_usage WHERE CAST(ts AS DATE)=CAST(now() AS DATE)")
        return {"tokens": int(r["tokens"]), "usd": float(r["usd"])}

    def usage_total(self) -> dict:
        r = self.db.query_one(
            "SELECT coalesce(sum(tokens_in+tokens_out),0) AS tokens, coalesce(sum(cost_usd),0) AS usd FROM ai_usage")
        return {"tokens": int(r["tokens"]), "usd": float(r["usd"])}

    def _check_budget(self) -> None:
        u = self.usage_today()
        if u["usd"] >= float(self.db.get_setting("ai_daily_usd_cap")):
            raise AIBudgetExceeded(f"daily USD cap reached ({u['usd']:.4f})")
        if u["tokens"] >= int(self.db.get_setting("ai_daily_token_cap")):
            raise AIBudgetExceeded(f"daily token cap reached ({u['tokens']})")
        total = self.usage_total()
        total_cap = float(self.db.get_setting("ai_total_usd_budget", 10.0))
        if total["usd"] >= total_cap:
            raise AIBudgetExceeded(f"total lifetime USD cap reached ({total['usd']:.4f} / {total_cap:.2f})")

    # -- call -----------------------------------------------------------------------
    def chat(self, messages: list[dict], *, agent: str, model: str | None = None, max_tokens: int = 1500,
             json_mode: bool = False, tools: list[dict] | None = None, temperature: float = 0.1) -> LLMResponse:
        if not self.is_enabled():
            raise AIDisabledError("ai_enabled is false")
        self._check_budget()
        key = self._key()
        model = model or self.db.get_setting("ai_default_model")
        payload: dict = {"model": model, "messages": messages, "max_tokens": max_tokens,
                         "temperature": temperature, "usage": {"include": True}}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        if tools:
            payload["tools"] = tools
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
                   "X-Title": "siempl"}
        data = self.transport(OPENROUTER_URL, headers, payload)
        msg = (data.get("choices") or [{}])[0].get("message", {})
        usage = data.get("usage", {}) or {}
        tin, tout = int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
        cost = usage.get("cost")
        if cost is None:
            cost = (tin * float(self.db.get_setting("ai_price_in_per_mtok")) +
                    tout * float(self.db.get_setting("ai_price_out_per_mtok"))) / 1e6
        self.db.execute("INSERT INTO ai_usage(agent,model,tokens_in,tokens_out,cost_usd) VALUES (?,?,?,?,?)",
                        [agent, model, tin, tout, float(cost)])
        return LLMResponse(text=msg.get("content") or "", model=model, tokens_in=tin, tokens_out=tout,
                           cost_usd=float(cost), tool_calls=msg.get("tool_calls") or [], raw=data)
