"""Regex table for the prompt-injection detector in _safety.py.

Each entry is (finding name, compiled pattern). Names are stable identifiers that appear in
audit rows, recommendations and agent output, so keep them short and snake_case.
Patterns are heuristics: they flag, they never decide. Triage treats any hit as "hold for human".
"""
from __future__ import annotations

import re

_FLAGS = re.IGNORECASE

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction_override", re.compile(
        r"\b(ignore|disregard|forget|override|skip)\s+(all\s+|any\s+|the\s+|your\s+|of\s+)*"
        r"(previous|prior|above|earlier|preceding|system|original)\s+"
        r"(instructions?|prompts?|rules?|messages?|directions?|guidelines?|context)", _FLAGS)),
    ("ignore_instructions", re.compile(r"\bignore\s+(all\s+)?(instructions|rules|guidelines)\b", _FLAGS)),
    ("role_reassign", re.compile(
        r"\byou\s+(are|'re)\s+now\s+(a|an|the|in|my|acting|dan|free|no longer)\b"
        r"|\bact\s+as\s+(an?\s+)?(unrestricted|unfiltered|admin|root)\b"
        r"|\bnew\s+(instructions|role|task)\s*:", _FLAGS)),
    ("role_marker", re.compile(r"^\s*(system|assistant|developer)\s*[:>]\s*\S", _FLAGS | re.MULTILINE)),
    ("chat_tokens", re.compile(
        r"<\|[a-z_]+\|>|\[/?INST\]|<</?SYS>>|<\s*/?\s*(system|assistant|im_start|im_end)\s*>", _FLAGS)),
    ("verdict_directive", re.compile(
        r"\b(mark|set|label|classify|consider|treat|record)\s+(this|the|these|that|it|alert|event|incident)\b"
        r"[^.\n]{0,40}\b(as\s+)?(closed|false[\s_-]?positive|benign|resolved|dismissed|fp)\b", _FLAGS)),
    ("close_directive", re.compile(
        r"\b(close|dismiss|resolve)\s+(this|the|these|all)\s+(alerts?|incidents?|events?)\b", _FLAGS)),
    ("disable_directive", re.compile(
        r"\b(disable|turn\s+off|suppress|whitelist|allowlist|delete)\s+(this|the|all|that)?\s*"
        r"(rules?|detections?|alerts?|sensors?|monitoring)\b", _FLAGS)),
    ("fake_verdict", re.compile(
        r"\"?verdict\"?\s*[:=]\s*\"?(true_positive|false_positive|benign|needs_human)\b"
        r"|\"status\"\s*:\s*\"closed_(tp|fp)\""
        r"|\"recommended_actions\"\s*:", _FLAGS)),
    ("fake_tool_result", re.compile(
        r"<\s*/?\s*tool[_ -]?(call|result|response|output)"
        r"|\btool[_ ]?(result|output|response)\s*[:=]"
        r"|\bfunction[_ ]?call\s*[:=]\s*\{"
        r"|<\s*/?\s*function[_ -]?(call|result|response)", _FLAGS)),
    ("prompt_leak", re.compile(
        r"\b(reveal|print|show|repeat|output|leak)\s+(your|the|system)\s+(system\s+)?"
        r"(prompt|instructions|configuration)", _FLAGS)),
    ("jailbreak", re.compile(r"\b(jailbreak|developer\s+mode|do\s+anything\s+now|DAN\s+mode)\b", _FLAGS)),
    ("authority_claim", re.compile(
        r"\b(admin|administrator|operator|owner|developer|anthropic|openai)\s+"
        r"(has\s+)?(authori[sz]ed|approved|instructs?|requests?|ordered)\b", _FLAGS)),
    ("fence_lookalike", re.compile(r"<<<|>>>|\bnonce\s*=\s*[0-9a-f]{4,}", _FLAGS)),
    ("active_markup", re.compile(
        r"<\s*(script|iframe|img|svg|object|embed|style|meta|link)\b|javascript\s*:"
        r"|\bon(error|load|click|mouseover)\s*=", _FLAGS)),
    ("markdown_injection", re.compile(r"!\[[^\]]*\]\(\s*https?://|\[[^\]]*\]\(\s*javascript:", _FLAGS)),
    ("exfil_directive", re.compile(
        r"\b(send|post|upload|exfiltrate|forward)\b[^\n]{0,60}\b(to|at)\s+https?://", _FLAGS)),
    ("escape_sequences", re.compile(r"(\\x[0-9a-fA-F]{2}){8,}|(%[0-9A-Fa-f]{2}){8,}")),
]

# Base64-looking blob (>= 32 chars). Checked in code together with DECODE_RE.
BLOB_RE = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
DECODE_RE = re.compile(r"\b(decode|base64|b64|eval|exec|execute|unhex)\b", _FLAGS)
