# Code standards (siempl)

> **Audience:** every human or agent that edits `siempl/`. Read this before changing code.
> **Goal:** the codebase gets easier to change over time, never harder.
> **Origin:** written 2026-10-13 after a measured baseline .
> Numbers below are measured on this repo, not copied from a blog.

## The rule that matters most: the ratchet

The code is ~19k lines, mostly written by LLM agents, and it has real debt (see "Baseline").
We do not fix it all at once and we do not let it get worse. `scripts/check_quality.py`
compares the tree to `docs/quality-baseline.json` and **fails if anything regressed**:

| Check | Rule |
|---|---|
| Function complexity (radon CC) | New functions: **<= 10**. Existing functions: never above their baseline (or 10, whichever is higher). |
| File length | New files: **<= 500 lines**. Files already over 500: may not grow. |
| Broad / swallowed exceptions (ruff `BLE001`, `S110`, `S112`) | Per-file count may never rise. |

Workflow:

```bash
.venv/bin/python -m pytest -q                 # tests (full suite ~4 min)
uvx ruff check siempl tests scripts           # must print "All checks passed!"
python3 scripts/check_quality.py              # must print "ok"
python3 scripts/check_quality.py --update     # ONLY after you improved something; commit the new baseline
```

**Git hooks (versioned in `scripts/hooks/`).** Run `./scripts/install_hooks.sh` once per clone.
`pre-commit` runs ruff + the ratchet (~5s); `pre-push` runs the full suite (~4.5 min). Anything that
commits here, human or agent, goes through them. `--no-verify` needs a written reason in the commit message.

`--update` is a one-way door in practice: never run it to make a failing check pass.
If a check fails, fix the code. If you honestly cannot, say so in the PR/commit and ask a human.

## Complexity and size

- Target: functions **<= 10 CC** (radon rank A/B), **<= 50 lines**, files **<= 500 lines**.
  These are directional. The CI-style gate above is what is enforced.
- When you touch a function that is over 10, leave it **lower** than you found it. Extract
  helpers rather than adding another `elif`.
- Prefer a table (dict of handlers) over a long `if/elif` chain. The big offenders in this
  repo (`_compile_func_call`, `_compile_binary_op`, `parse_cef`, `tokenize`) are exactly that.
- Do not split a file just to hit a number. Split along a real seam (one reason to change).

## Error handling

- **Never** `except:` and never `except Exception: pass`.
- If you catch broadly (`except Exception`), you must do one of: log it with
  `logger.exception(...)` / `logger.warning(..., exc_info=True)`, return a typed error the caller
  handles, or re-raise. "Best effort" is allowed only for genuinely optional work, and then it
  must still log at DEBUG with context.
- Catch the narrowest type you can name (`ValueError`, `duckdb.Error`, `json.JSONDecodeError`).
- Use `raise ... from e` when translating an exception.
- A swallowed error in an agent code path is a bug, not a style issue: it makes a failing
  detection look like "no alerts".

## Lint and format

Config lives in `pyproject.toml` (`[tool.ruff]`, line length 120, py311).

- Enabled: `F E W I B UP SIM BLE S110 S112 RET C4 PIE`. `S110`/`S112` are now at zero and enforced (removed from `ignore`). Enforced in `siempl/`; `tests/` and `scripts/` are exempt via `per-file-ignores`.
- The `ignore` list there is the **ratchet list**: rules with known existing violations.
  When a rule's count reaches zero, delete it from `ignore`. **Never add to it.**
- No `# noqa` without a rule code and a reason. A `noqa` that suppresses a real bug is a
  regression (see the `_AGENT_BASE` NameError found in routes.py on 2026-10-13).
- Remove dead code instead of commenting it out. Git remembers.

## Tests

- Every bug fix gets a test that fails before the fix.
- **Before refactoring code that lacks tests, write a characterization test first**: capture what
  it does today (golden output), then refactor in small steps keeping that test green.
- Never weaken or delete an assertion to make a test pass. Never `assert x` where the thing
  being tested is "does not raise". Assert on behavior.
- Do not refactor and change behavior in the same commit.
- **A behavior-preservation check must be able to fail.** Prove it: run it once against a deliberately
  broken change. Compare against the pre-change git ref (a worktree), never against a snapshot produced by the
  same code, and never trust a child agent's "identical" without re-running the comparison yourself. For the
  KQL compiler use `scripts/compare_kql_vs_ref.sh`.
- Full suite must pass before every commit that touches `siempl/`. Report the pass count.

## Commits and process

- One logical change per commit; message says **why**. Mechanical changes (formatting,
  autofix) are separate from behavior changes so review and rollback stay cheap.
- Commit before any multi-section rewrite so a bad edit is `git checkout -- file`.
- Do not hand-edit generated or vendored files (`siempl/web/static/htmx.min.js`).
- Reports from agents ("done", "tests pass") are claims. Verify with the command output.

## Agent instruction files (AGENTS.md, CLAUDE.md, docs/AGENTS.md)

- Written by a human or reviewed by one; do not let an LLM auto-generate and commit them.
- Keep the root instruction file short (under ~200 lines): commands, conventions, boundaries,
  and where to look. Put details in `docs/`. Do not restate what the code already says.
- Update the docs in the same commit as the behavior change.

## Architecture

- Dependency direction: `web` and `agents` call into `detect`, `ingest`, `kql`, `entities`,
  `db`; those must not import from `web`. Check with the graph (`graphify`) when in doubt.
- New HTTP routes go in a `routes_<area>.py` module (auto-mounted before `routes.py`).
  Do not add to `routes.py`; it is legacy and is being drained.
- One route, one handler. A duplicate path silently shadows the other (first mounted wins).

## Documentation

Documentation is part of the change, not a follow-up. A change is not done until the docs match it.

- **Same commit:** if you change behavior, a module's responsibilities, a file layout, a config key or a
  command, update the matching doc (`ARCHITECTURE.md`, `KQL.md`, `PARSERS.md`, `AGENTS.md`, `UI.md`, `OPERATIONS.md` ...) in that commit.
- **Every module starts with a docstring** saying what it is for and what it is *not* for (one to three
  lines). Splitting a file creates new modules: each one gets this docstring, and the old module's docstring
  says where the pieces went.
- **Public functions and classes** get a docstring stating inputs, outputs and side effects when that is
  not obvious from the signature. Do not narrate the code line by line.
- **Comments explain why**, not what. Link the doc or decision (`DECISIONS.md`, `docs/adr/`) for non-obvious choices.
- **Record decisions.** A choice a future reader would question (a threshold, a workaround, a rejected
  option) goes in `DECISIONS.md` or a new ADR with the reason.
- **Keep the history.** Larger cleanups get a written record in the commit message: what changed, how it was verified,
  what broke, what is left.
- **Docs must be checkable.** Prefer commands someone can paste and run over prose claims. Numbers in docs
  (test counts, line counts) are dated or generated, never hand-waved.

## Baseline (2026-10-13)

| Metric | Before cleanup | 2026-10-13 after cleanup |
|---|---|---|
| Functions over CC 10 | 84 (max 73: `ingest/ocsf.py::_one`) | 70 (max 34: `ingest/mapping.py::validate_spec`) |
| Functions over CC 20 | 32 | 18 |
| Files over 500 lines | 14 (largest `ingest/parsers.py`, 2424) | 10 (largest `detect/engine.py`, 1310) |
| Broad `except` findings (ruff BLE001 + S110 + S112) | ~257 | 100 (the 78 silent ones now log) |
| Ruff findings (project config) | 679 | 0 |
| Tests | 692 | 853 |

The enforced numbers live in `docs/quality-baseline.json`.

Progress is tracked by re-running `scripts/check_quality.py` and diffing the baseline.
