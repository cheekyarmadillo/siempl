"""Characterization tests for siempl.agents.onboarding helpers.

Golden values were captured from the pre-refactor code. They lock current behavior so the
helpers can move into _onboarding_analysis.py / _onboarding_llm.py without changing output.
"""

import json
from collections import Counter

from siempl.agents import onboarding as O
from siempl.ai.llm import AIDisabledError

SAMPLES_JSON = [
    json.dumps({"user": "bob", "ip": "10.0.0.1", "method": "login", "timestamp": "2026-01-01T00:00:00Z"}),
    json.dumps({"user": "alice", "ip": "10.0.0.2", "method": "logout"}),
]
SAMPLES_KV = ['src=10.1.1.1 dst=10.2.2.2 user="jo smith" action=allow', "src=10.1.1.3 dst=10.2.2.4 action=deny"]
SAMPLES_CSV = ["2026-01-01,bob,login", "2026-01-02,alice,logout"]
SAMPLES_RE = ["hello 10.0.0.9 at 12:30:00", "plain text 10.0.0.8 12:31:00"]


class TestAnalyzeAndProposeGolden:
    def test_json_samples(self):
        a = O._analyze_samples(SAMPLES_JSON)
        assert a == {
            "counts": {"csv": 0, "json": 2, "kv": 0},
            "field_examples": {"ip": ["10.0.0.1", "10.0.0.2"], "method": ["login", "logout"],
                               "timestamp": ["2026-01-01T00:00:00Z"], "user": ["bob", "alice"]},
            "format": "json",
            "json_keys": {"ip": 2, "method": 2, "timestamp": 1, "user": 2},
            "keys": {},
            "total": 2,
        }
        spec = O._propose_heuristic_spec("my-src/x", a)
        assert spec == {
            "constants": {}, "description": "Auto-generated mapping for source my-src/x",
            "fields": {"HttpMethod": "$.method", "SrcIp": "$.ip", "TimeGenerated": "$.timestamp",
                       "UserName": "$.user"},
            "format": "json", "name": "mapping_my_src_x", "target_table": "AuthEvents",
            "time": {"field": "$.timestamp", "format": "iso8601"},
        }
        assert O._verify_coverage(spec, SAMPLES_JSON) == {
            "coverage_pct": 100.0, "errors": [], "parsed": 2, "total": 2}

    def test_kv_samples(self):
        a = O._analyze_samples(SAMPLES_KV)
        assert a["format"] == "kv"
        assert a["keys"] == {"action": 2, "dst": 2, "src": 2, "user": 1}
        assert a["field_examples"]["user"] == ['"jo smith"']
        spec = O._propose_heuristic_spec("my-src/x", a)
        assert spec["fields"] == {"EventAction": "action", "SrcIp": "src", "UserName": "user"}
        assert spec["description"] == "Auto-generated mapping for source my-src/x. Unmapped fields: dst."
        assert O._verify_coverage(spec, SAMPLES_KV)["coverage_pct"] == 100.0

    def test_csv_samples_have_no_aliases(self):
        a = O._analyze_samples(SAMPLES_CSV)
        assert a["format"] == "csv"
        assert a["keys"] == {"col1": 2, "col2": 2, "col3": 2}
        spec = O._propose_heuristic_spec("my-src/x", a)
        assert spec["fields"] == {}
        assert spec["target_table"] == "GenericEvents"
        cov = O._verify_coverage(spec, SAMPLES_CSV)
        assert cov["coverage_pct"] == 0.0
        assert cov["errors"] == ["sample[0]: no meaningful fields mapped",
                                 "sample[1]: no meaningful fields mapped"]

    def test_regex_samples(self):
        a = O._analyze_samples(SAMPLES_RE)
        assert a["format"] == "regex"
        assert a["keys"] == {"ip": 2, "timestamp": 2}
        spec = O._propose_heuristic_spec("my-src/x", a)
        assert spec["fields"] == {"SrcIp": "ip", "TimeGenerated": "timestamp"}
        assert spec["description"].endswith("REGEX format requires manual pattern configuration.")
        cov = O._verify_coverage(spec, SAMPLES_RE)
        assert cov["coverage_pct"] == 0.0
        assert cov["errors"] == ["sample[0]: parser returned no events",
                                 "sample[1]: parser returned no events"]

    def test_analyze_empty_and_propose_unknown(self):
        assert O._analyze_samples([]) == {"format": "unknown", "fields": {}, "stats": {}}
        spec = O._propose_heuristic_spec("s", {"format": "unknown", "json_keys": {}})
        assert spec["format"] == "json"
        assert spec["target_table"] == "GenericEvents"


class TestSmallHelpers:
    def test_guess_target_table(self):
        assert O._guess_target_table(["username", "ip", "method"]) == "AuthEvents"
        assert O._guess_target_table(["zzz"]) == "GenericEvents"
        assert O._guess_target_table([]) == "GenericEvents"

    def test_parse_samples_return_flags(self):
        keys: Counter = Counter()
        ex: dict = {}
        assert O._parse_kv_sample("a=1 b=2", keys, ex) is True
        assert keys == Counter({"a": 1, "b": 1})
        assert O._parse_kv_sample("a=1", Counter(), {}) is False
        assert O._parse_csv_sample("x", Counter(), {}) is False
        assert O._parse_json_sample("[1]", Counter(), {}) is False
        assert O._parse_json_sample('{"k": 1}', Counter(), {}) is True

    def test_add_field_example_caps_at_three(self):
        ex: dict = {}
        for v in ["a", "b", "c", "d"]:
            O._add_field_example(ex, "k", v)
        assert ex == {"k": ["a", "b", "c"]}

    def test_detect_parser_no_match_shape(self):
        res = O._detect_parser(["just some text"], "s1")
        assert set(res) == {"parser", "hits", "total", "table", "all_hits"}
        assert res["total"] == 1


class _Resp:
    def __init__(self, obj):
        self._obj = obj

    def json(self):
        return self._obj


class _FakeAgent:
    """Stands in for OnboardingAgent: only ai_chat is used by the LLM helpers."""

    def __init__(self, replies=None, error=None):
        self.replies = list(replies or [])
        self.error = error
        self.calls = 0

    def ai_chat(self, messages, json_mode=False, max_tokens=None):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return _Resp(self.replies.pop(0))


GOOD_SPEC = {"name": "llm", "target_table": "AuthEvents", "format": "json",
             "fields": {"UserName": "$.user"}, "description": "from llm"}


class TestLLMHelpers:
    def test_llm_propose_spec_returns_dict_with_target_table(self):
        agent = _FakeAgent(replies=[GOOD_SPEC])
        spec = O._llm_propose_spec(agent, "src", {"format": "json"}, SAMPLES_JSON)
        assert spec == GOOD_SPEC
        assert agent.calls == 1

    def test_llm_propose_spec_rejects_missing_target_table(self):
        assert O._llm_propose_spec(_FakeAgent(replies=[{"fields": {}}]), "s", {}, []) is None

    def test_llm_propose_spec_swallows_errors(self):
        assert O._llm_propose_spec(_FakeAgent(error=RuntimeError("boom")), "s", {}, []) is None

    def test_try_fix_returns_valid_fixed_spec(self):
        agent = _FakeAgent(replies=[GOOD_SPEC])
        bad = {"name": "x"}
        assert O._try_fix_llm_spec(agent, bad) == GOOD_SPEC

    def test_try_fix_returns_none_on_error(self):
        assert O._try_fix_llm_spec(_FakeAgent(error=RuntimeError("x")), {"name": "x"}) is None

    def test_merge_valid_llm_spec_overrides_fields(self):
        heur = {"name": "h", "target_table": "GenericEvents", "fields": {"A": "$.a"}, "constants": {}}
        O._merge_llm_spec(_FakeAgent(), heur, GOOD_SPEC)
        assert heur["target_table"] == "AuthEvents"
        assert heur["fields"] == {"UserName": "$.user"}
        assert heur["description"] == "from llm"
        assert heur["name"] == "h"  # name is never merged

    def test_merge_invalid_llm_spec_without_fix_leaves_heuristic(self):
        heur = {"name": "h", "target_table": "GenericEvents", "fields": {"A": "$.a"}}
        before = dict(heur)
        O._merge_llm_spec(_FakeAgent(error=RuntimeError("no")), heur, {"name": "bad"})
        assert heur == before

    def test_maybe_enrich_merges_when_llm_answers(self):
        heur = {"name": "h", "target_table": "GenericEvents", "fields": {}}
        O._maybe_enrich_with_llm(_FakeAgent(replies=[GOOD_SPEC]), heur, "s", {}, SAMPLES_JSON)
        assert heur["target_table"] == "AuthEvents"

    def test_maybe_enrich_swallows_ai_disabled(self):
        heur = {"name": "h", "target_table": "GenericEvents", "fields": {}}
        O._maybe_enrich_with_llm(_FakeAgent(error=AIDisabledError("off")), heur, "s", {}, [])
        assert heur == {"name": "h", "target_table": "GenericEvents", "fields": {}}

    def test_maybe_enrich_leaves_heuristic_on_llm_error(self):
        heur = {"name": "h", "target_table": "GenericEvents", "fields": {}}
        O._maybe_enrich_with_llm(_FakeAgent(error=RuntimeError("bad")), heur, "s", {}, [])
        assert heur == {"name": "h", "target_table": "GenericEvents", "fields": {}}
