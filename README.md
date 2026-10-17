# siempl

**siempl** is an agentic SIEM I built to show what a security platform looks like when AI is designed in from the start instead of bolted on. It's a single Python process: DuckDB for storage, a KQL query engine, detection rules (including Sigma import), and an alert and incident workflow in a web UI. Agents for triage, rule tuning, rule discovery, log-source onboarding, and ingestion cost optimization work inside the same pages the analyst already uses.

I've worked with SIEMs like Microsoft Sentinel and CrowdStrike, and the AI in most of them is an assistant sitting next to the product, like Copilot, instead of something that does the work. I wanted native agents that take on jobs a consultant would charge tens of thousands of dollars for, like finding noisy rules, trimming ingestion cost, and onboarding new log sources. Because logs are attacker-controlled input, I built the agents to be safe to trust: every action is auditable, what each agent may do is set by a permissions matrix enforced in code (not in the prompt), and they resist prompt injection from log content, backed by a 64-string attack corpus in the test suite. AI is off by default and runs as recommendations first, behind a kill switch and hard spend caps. GPT-5.6 Sol was tested against other frontier models and found to work best for these agents, identifying 0 false positives and achieving 94.4% accuracy. I built the whole project using OpenClaw and teams of subagents.

![Overview](docs/screenshots/overview.png)

## Contents

- [Quickstart](#quickstart)
- [Features](#features)
- [Agents](#agents)
- [Safety model](#safety-model)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Sample data](#sample-data)
- [Development](#development)
- [Documentation](#documentation)
- [License](#license)

## Quickstart

Requires Python 3.11+.

```bash
git clone https://github.com/cheekyarmadillo/siempl.git && cd siempl
python -m venv .venv && source .venv/bin/activate
pip install -e .

python -m siempl            # web UI on http://127.0.0.1:8765
```

Useful flags:

| Flag | Effect |
|------|--------|
| `--port N` | Override the web port (default 8765) |
| `--host` | Listen on all interfaces, dual-stack IPv4 + IPv6 (default is loopback only) |
| `--no-collectors` | Do not start the syslog / HTTP / file collectors |
| `--no-scheduler` | Do not start the rule and agent schedulers |

No API key is needed for anything except the LLM features. To get data on screen fast, open **Samples** in the UI and load the synthetic data or the attack scenarios (see [Sample data](#sample-data)).

### Run as a service (Linux, systemd user unit)

```bash
scripts/install_service.sh --dry-run   # preview the unit
scripts/install_service.sh             # install, enable, start (loopback, restarts on failure, starts at boot)
scripts/install_service.sh --lan       # listen on all interfaces
scripts/install_service.sh --uninstall
```

> **There is no authentication yet.** Keep the default loopback bind, or put siempl behind a reverse proxy or SSH tunnel before exposing it.

## Features

### Overview

A one-screen dashboard: events per hour, open alerts by severity, alerts created per hour, top rules, top entities by reputation, source health, events by table, recent agent runs and AI spend. The range switches between 1h, 24h and 7d.

### Logs and KQL

![Logs](docs/screenshots/logs.png)

- Query every table with a KQL subset compiled to DuckDB SQL (`where`, `project`, `summarize`, `order by`, `take`, `join`, `let`, `ago()`, `bin()`, regex and more). Real query errors are shown, not swallowed.
- Table browser, query history, time-range picker and a row limit that can be switched off.
- Bar and pie charts, a pivot view, and CSV or JSON export of the full result.

Tables: `Syslog`, `AuthEvents`, `ProcessEvents`, `NetworkEvents`, `WebAccess`, `FileEvents`, `GenericEvents`, `SiemplAudit`. See [docs/KQL.md](docs/KQL.md).

### Alerts

![Alerts](docs/screenshots/alerts.png)

Alerts and incidents are one object. Every alert gets a number (`#1042`) and one of four statuses: **New**, **Active**, **Closed - True Positive**, **Closed - False Positive**.

- Open-alerts-by-severity pie and status bars; every slice and bar is a filter link.
- Change status and severity inline, in bulk, or from the detail page; assign an owner; comment.
- Click a row for a side preview, or open the full alert page with description, evidence rows, entities, MITRE ATT&CK techniques, rule, history and comments.
- Filter by severity, status, free text or rule (`?rule=<id>`); the charts follow the filter.

![Alert detail](docs/screenshots/alert-detail.png)

### Detection rules

![Rule detail](docs/screenshots/rule-detail.png)

- Rules are KQL queries with a frequency, lookback window and threshold, plus description, triage steps and MITRE mapping.
- 22 built-in rules, a rule editor with **Test run** and **Run now**, clone, enable/disable and tuning history.
- Import Sigma rules (converted to KQL) and adapt Microsoft Sentinel analytic rules by hand. See [docs/RULES.md](docs/RULES.md), [docs/SENTINEL.md](docs/SENTINEL.md).
- Each rule shows the alerts it created, with status counts.

![Rules](docs/screenshots/rules.png)

### Ingestion

![Ingestion](docs/screenshots/ingestion.png)

- Collectors: syslog (UDP and TCP, default port 5514), HTTP ingest endpoint, and file tail. Add, edit, start and stop sources from the UI.
- Built-in parsers: syslog RFC 3164 and 5424, CEF, Apache combined, generic JSON, Windows JSON, Windows XML, Zeek conn and DNS, OCSF. Auto-detection picks a parser for new sources.
- Declarative **mapping parsers** (JSON, key=value with optional delimiter, CSV, regex) for formats nothing else handles, validated before use. See [docs/PARSERS.md](docs/PARSERS.md).
- Ingest-time drop filters and per-table retention.
- Overview graphs: events over time, events by table, active versus stale sources, events dropped by filters.

### Entities

![Entities](docs/screenshots/entities.png)

Users, hosts, IPs, processes and domains are extracted from events and tracked with a reputation score, a last-detected time, the tables they appear in and the alerts they are part of. Alert verdicts feed the score. See [docs/ENTITIES.md](docs/ENTITIES.md).

### Audit and settings

Status changes, rule and source edits, recommendation approvals, agent runs, policy and settings changes are written to an audit log. Settings hold the AI kill switch, model choice, budget caps and the OpenRouter key entry (write-only, never displayed).

## Agents

![Agents](docs/screenshots/agents.png)

Agents live in the pages they act on, and everything they propose lands in one **Needs your attention** queue. Approve or reject; a red dot appears on a portal only when something is waiting for a human.

| Agent | Where | What it does |
|-------|-------|--------------|
| **Triage** | Alerts | Reads an alert, its evidence and related entities, then proposes a verdict (true positive, false positive, needs human) with confidence and next steps. A deterministic path (rule history, repetition, kill-chain, reputation) works without an LLM. |
| **Tuning** | Rules | Finds noisy rules and repeat false-positive entities; proposes threshold changes, entity exclusions or disabling the rule. |
| **Rule discovery** | Rules | Validates sources, imports Sigma rules, and proposes baseline and LLM-written rules (always disabled until you enable them). |
| **Onboarding** | Ingestion | Looks at raw samples from a new source and picks a built-in parser or proposes a mapping parser with measured coverage. Never auto-applied below 50% coverage. |
| **Optimizer** | Ingestion | Finds unused tables and noisy sources; proposes retention changes and ingest filters. |
| **Log alert** | Logs | Scans new log lines for suspicious templates and raises alerts. |
| **Remediation** | Alerts | Connector interface for response actions. Connectors are stubs. |

What an agent may do is controlled by a **policy matrix** (per agent, severity or rule): mode (off, monitor, recommend, auto-close, auto-remediate), and whether it may close, escalate, remediate or create temporary rules. The policy is enforced in code, not in the prompt.

See [docs/AGENTS-GUI.md](docs/AGENTS-GUI.md) and [docs/AGENTS.md](docs/AGENTS.md).

### Prompt-injection resistance

Logs are attacker-controlled input, so agents treat them that way:

- telemetry is fenced and labelled as untrusted data before an LLM sees it
- model output must match a strict schema; anything else becomes *needs human*
- a detector scans telemetry for instruction-like content and **holds the alert for a human** instead of acting
- an agent can never exceed what the policy matrix allows, whatever the model says
- a corpus of 64 attack strings is run against every agent in the test suite

## Safety model

1. **AI is off by default.** No LLM call happens until it is enabled in Settings and a key exists.
2. **Agents recommend first.** Dry-run is the default; changes need an approval unless the policy matrix says otherwise.
3. **The key is never stored in the database or shown in the UI.** It lives in `OPENROUTER_API_KEY` or `~/.config/siempl/openrouter.key`.
4. **Hard caps.** Daily USD and token caps, plus a lifetime budget (default 10 USD), are checked before every LLM call, and every call goes through one client.
5. **Kill switch** in Settings disables AI and scheduling at once.
6. **Remediation connectors are stubs**, even when enabled.

## Architecture

```
collectors (syslog / http / file) -> parsers -> typed tables (DuckDB)
                                          |            |
                                          v            v
                                   entity store     KQL engine <- web UI / API
                                                       |
                                              detection rules -> alerts
                                                       |
                                                    agents (OpenRouter)
```

| Layer | Technology |
|-------|------------|
| Storage | DuckDB (embedded, columnar) |
| Query | KQL subset compiled to DuckDB SQL (`siempl/kql`) |
| Rules | KQL, Sigma import (pySigma) |
| Web | FastAPI, Jinja2, HTMX, server-rendered SVG charts, no JS build step |
| LLM | OpenRouter, one chokepoint (`siempl/ai/llm.py`) |
| Process | One process: web server, collectors and schedulers |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module contracts.

## Configuration

- Data lives in `./data` (override with `SIEMPL_HOME`). It contains the DuckDB file and caches. Only one process can open the database at a time.
- Settings (bind host and port, syslog ports, AI switches, caps, model) are stored in the database and edited on the Settings page.
- `OPENROUTER_API_KEY` or `~/.config/siempl/openrouter.key` enables the LLM features.
- Back up by stopping siempl and copying `data/siempl.duckdb`. See [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Sample data

The **Samples** page loads data so every screen has something in it:

- synthetic Windows, syslog and network events
- seven attack and noise **scenarios** (brute force, lateral movement, exfiltration, a noisy backup account, a chatty debug source, an unparsed IoT source, and log lines that contain prompt-injection attempts), each with a manifest of the expected triage outcome, used to evaluate the agents

Details in [docs/TESTDATA.md](docs/TESTDATA.md).

## Development

```bash
pip install -e . pytest ruff
SIEMPL_HOME=$(mktemp -d) python -m pytest -q       # about 1,650 tests, around 9 minutes
ruff check siempl tests scripts
python scripts/check_quality.py                      # complexity and size ratchet
scripts/install_hooks.sh                             # run the checks before every commit
```

Code standards and the quality ratchet are in [docs/STANDARDS.md](docs/STANDARDS.md). Read it before editing code.

## Documentation

| Doc | Contents |
|-----|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules and contracts |
| [UI.md](docs/UI.md) | Web interface and API reference |
| [KQL.md](docs/KQL.md) | The KQL compiler |
| [PARSERS.md](docs/PARSERS.md) | Built-in and mapping parsers |
| [INGESTION.md](docs/INGESTION.md) | Collectors and the ingest pipeline |
| [DETECT.md](docs/DETECT.md), [RULES.md](docs/RULES.md) | Detection engine and rules |
| [ENTITIES.md](docs/ENTITIES.md) | Entity store and reputation |
| [AGENTS.md](docs/AGENTS.md), [AGENTS-GUI.md](docs/AGENTS-GUI.md) | Agents, policy matrix, injection defences |
| [OPERATIONS.md](docs/OPERATIONS.md) | Deployment, backup, troubleshooting |
| [STANDARDS.md](docs/STANDARDS.md) | Code standards |
| `docs/adr/` | Architecture decision records |

## Known limitations

- No authentication or multi-user support yet.
- Remediation connectors are stubs.
- Sigma import covers a subset of the rule language; some rules are unsupported and are reported as such.
- Single node, single process. DuckDB allows one writer process.

## License

[MIT](LICENSE)
