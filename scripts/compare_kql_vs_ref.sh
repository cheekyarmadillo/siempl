#!/usr/bin/env bash
# Behavior-preservation check for KQL compiler/tokenizer/parser refactors.
# Compiles the same query corpus on git REF (default: tag quality-baseline) and on the working tree and
# reports (a) queries whose SQL changed, (b) queries that flipped between compiling and erroring.
# The corpus is harvested from the CURRENT tests/ and docs/KQL.md, copied into the REF checkout, so both
# sides see identical inputs. A pure refactor should print: SQL differs: 0   ok<->error flips: 0.
#
#   scripts/compare_kql_vs_ref.sh [REF]
set -euo pipefail
REF="$*"
if [ -z "$REF" ]; then REF=quality-baseline; fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WT="$(mktemp -d)/ref"
OUT="$(mktemp -d)"
PY="$ROOT/.venv/bin/python"
git -C "$ROOT" worktree add -f "$WT" "$REF" -q
trap 'git -C "$ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || true; git -C "$ROOT" worktree prune' EXIT
rm -rf "$WT/tests" && cp -r "$ROOT/tests" "$WT/tests" && cp "$ROOT/docs/KQL.md" "$WT/docs/KQL.md"
(cd "$WT" && SIEMPL_HOME="$(mktemp -d)" "$PY" "$ROOT/scripts/kql_corpus_snapshot.py" "$OUT/ref.json")
(cd "$ROOT" && SIEMPL_HOME="$(mktemp -d)" "$PY" scripts/kql_corpus_snapshot.py "$OUT/now.json")
python3 - "$OUT/ref.json" "$OUT/now.json" "$REF" <<'EOF'
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
ea = {e["query"]: e["error"] for e in a["errors"]}
eb = {e["query"]: e["error"] for e in b["errors"]}


def st(ok, er, q):
    return "ok" if q in ok else ("err" if q in er else "absent")


diff, flips, absent = [], [], 0
for q in sorted(set(a["ok"]) | set(ea) | set(b["ok"]) | set(eb)):
    x, y = st(a["ok"], ea, q), st(b["ok"], eb, q)
    if "absent" in (x, y):
        absent += 1  # harvested from siempl/ source text, which differs between trees; not a compiler change
    elif x == "ok" and y == "ok" and a["ok"][q] != b["ok"][q]:
        diff.append(q)
    elif x != y:
        flips.append((q, x, y))
print("ref=%s  queries: ref ok=%d err=%d | now ok=%d err=%d" % (sys.argv[3], len(a["ok"]), len(ea), len(b["ok"]), len(eb)))
print("SQL differs: %d   ok<->error flips: %d   (only in one tree: %d)" % (len(diff), len(flips), absent))
for q in diff:
    print("  DIFF", q[:110].replace(chr(10), " "))
for q, x, y in flips:
    print("  FLIP", x, "->", y, q[:110].replace(chr(10), " "))
sys.exit(1 if flips else 0)
EOF
