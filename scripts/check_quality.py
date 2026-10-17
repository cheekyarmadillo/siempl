#!/usr/bin/env python3
"""Quality ratchet for siempl. See docs/STANDARDS.md.

Fails (exit 1) if code got WORSE than docs/quality-baseline.json:
  - a function's cyclomatic complexity rose, or a new function exceeds MAX_NEW_CC
  - a file grew past MAX_NEW_FILE_LINES (or grew at all if it was already over)
  - swallowed/blind exception count (ruff S110,S112,BLE001) rose in any package

Move-aware: splitting a module must not look like a regression. A function that is not in the baseline
under its new file is matched to a baseline function with the same qualified name in the same package, and
broad-except counts are compared per package (directory), not per file. Adding a new broad except anywhere
still fails; moving one between files of the same package does not.

  scripts/check_quality.py            check against baseline
  scripts/check_quality.py --update   rewrite baseline (only after IMPROVING things)
"""
from __future__ import annotations

import collections
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "docs" / "quality-baseline.json"
MAX_NEW_CC = 10
MAX_NEW_FILE_LINES = 500


def _run(cmd: list[str]) -> str:
    # radon/ruff are dev tools, not runtime deps: use them directly or via uvx.
    exe = shutil.which(cmd[0])
    full = cmd if exe else ["uvx", *cmd]
    return subprocess.run(full, cwd=ROOT, capture_output=True, text=True).stdout


def _pkg(path: str) -> str:
    """Package = the directory of a file (siempl/agents/x.py -> siempl/agents)."""
    return str(Path(path).parent)


def measure() -> dict:
    cc = json.loads(_run(["radon", "cc", "siempl", "-s", "-j"]) or "{}")
    funcs = {}
    for path, blocks in cc.items():
        for b in blocks:
            key = f"{path}::{b.get('classname') + '.' if b.get('classname') else ''}{b['name']}"
            funcs[key] = b["complexity"]
    lines = {
        str(p.relative_to(ROOT)): sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
        for p in (ROOT / "siempl").rglob("*.py")
    }
    ex = json.loads(_run(["ruff", "check", "siempl", "--select", "S110,S112,BLE001",
                          "--isolated", "--output-format", "json"]) or "[]")
    excepts = collections.Counter(str(Path(e["filename"]).relative_to(ROOT)) for e in ex)
    return {"cc": funcs, "lines": lines, "excepts": dict(excepts)}


def main() -> int:
    cur = measure()
    if "--update" in sys.argv:
        BASELINE.write_text(json.dumps(cur, indent=1, sort_keys=True) + "\n")
        print(f"baseline written: {len(cur['cc'])} functions, {sum(cur['excepts'].values())} broad excepts")
        return 0
    base = json.loads(BASELINE.read_text())
    bad: list[str] = []
    by_name = collections.defaultdict(list)  # (package, qualified name) -> baseline values
    by_bare = collections.defaultdict(list)  # (package, bare function name) -> baseline values
    for k, v in base["cc"].items():
        by_name[(_pkg(k.split("::")[0]), k.split("::", 1)[1])].append(v)
        by_bare[(_pkg(k.split("::")[0]), k.rsplit(".", 1)[-1].split("::")[-1])].append(v)
    for k, v in cur["cc"].items():
        if k in base["cc"]:
            known = base["cc"][k]
        else:  # not under this file in the baseline: was it moved from another file in the package?
            moved = by_name.get((_pkg(k.split("::")[0]), k.split("::", 1)[1]), [])
            if not moved:
                # A method moved into a different (mixin) class changes its qualified name. Accept the bare-name match
                # only when it is unambiguous: exactly one function of that name existed in the package baseline.
                bare = by_bare.get((_pkg(k.split("::")[0]), k.rsplit(".", 1)[-1].split("::")[-1]), [])
                moved = bare if len(bare) == 1 else []
            known = max(moved) if moved else MAX_NEW_CC
        allowed = max(known, MAX_NEW_CC)
        if v > allowed:
            bad.append(f"complexity {k}: {v} > allowed {allowed}")
    for f, n in cur["lines"].items():
        allowed = max(base["lines"].get(f, 0), MAX_NEW_FILE_LINES)
        if n > allowed:
            bad.append(f"file length {f}: {n} > allowed {allowed}")
    cur_pkg, base_pkg = collections.Counter(), collections.Counter()
    for f, n in cur["excepts"].items():
        cur_pkg[_pkg(f)] += n
    for f, n in base["excepts"].items():
        base_pkg[_pkg(f)] += n
    for pkg, n in cur_pkg.items():
        if n > base_pkg.get(pkg, 0):
            bad.append(f"broad/swallowed excepts in {pkg}/: {n} > baseline {base_pkg.get(pkg, 0)}")
    for b in bad:
        print("FAIL", b)
    tot = sum(cur["excepts"].values())
    over = sum(1 for v in cur["cc"].values() if v > MAX_NEW_CC)
    print(f"{'FAILED' if bad else 'ok'}: {over} functions over CC {MAX_NEW_CC}, {tot} broad excepts, "
          f"{sum(1 for n in cur['lines'].values() if n > MAX_NEW_FILE_LINES)} files over {MAX_NEW_FILE_LINES} lines")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
