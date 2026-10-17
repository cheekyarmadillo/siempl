# siempl Operations

How to run, configure, and maintain a siempl deployment.

## Quickstart

```bash
# Start everything (web server, collectors, rule scheduler, agent scheduler)
python -m siempl

# Open the web interface
open http://127.0.0.1:8765
```

## Command-Line Flags

| Flag | Effect |
|------|--------|
| `--host` | Bind to all interfaces (`::` dual-stack IPv4+IPv6, or 0.0.0.0 if IPv6 is unavailable) instead of 127.0.0.1 |
| `--port N` | Override bind port (default: 8765 from settings) |
| `--no-collectors` | Skip log collectors (syslog, HTTP ingest, file tail) |
| `--no-scheduler` | Skip rule scheduler and agent scheduler |

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `SIEMPL_HOME` | Data directory (default: `./data`). DB, rules cache, etc. |
| `OPENROUTER_API_KEY` | OpenRouter API key for AI features (optional) |

## Configuration

All runtime settings are stored in the `settings` table in DuckDB and managed
through the web UI at `/settings`. See `siempl/config.py` for defaults.

Key settings:
- `ai_enabled` (bool, default `false`): master kill switch for all LLM calls
- `ai_daily_usd_cap` (float): hard USD limit per UTC day
- `ai_daily_token_cap` (int): hard token limit per UTC day
- `agents_dry_run` (bool, default `true`): agents record actions but execute nothing
- `remediation_enabled` (bool, default `false`): even when enabled, connectors are stubs
- `bind_host` / `bind_port`: server bind (default `127.0.0.1:8765`)

### API Key Setup

Place your OpenRouter key in one of:
1. Environment variable: `export OPENROUTER_API_KEY=sk-or-...`
2. Key file: `~/.config/siempl/openrouter.key` (plaintext, one line)

The web UI shows key status as "found"/"not found" only. **Never paste the key
value into the web UI or settings API.**

## Ports

| Port | Purpose | Default |
|------|---------|---------|
| 8765 | Web UI + API (HTTP) | configurable via `bind_port` |
| 5514 | Syslog UDP (unprivileged default) | `syslog_udp_port` |
| 5514 | Syslog TCP | `syslog_tcp_port` |

The web server binds `127.0.0.1` by default (never `0.0.0.0` unless `--host`).
Use a reverse proxy (nginx, Caddy) for TLS termination and external access.

## Data Storage

All data lives under `SIEMPL_HOME` (default `./data/`):
```
data/
  siempl.duckdb       Database file (metadata, settings, entities, alerts, etc.)
  siempl.duckdb.wal   Write-ahead log (DuckDB internal)
  rules_cache/        Cached imported rules (Sigma, Sentinel)
```

## Backup

```bash
# Stop siempl first (DuckDB needs exclusive access for export)
cp data/siempl.duckdb data/siempl.duckdb.backup.$(date +%Y%m%d)

# Or use DuckDB export (while running, but may be inconsistent):
duckdb data/siempl.duckdb "EXPORT DATABASE 'backup_dir' (FORMAT PARQUET)"
```

The database file is the only persistent state. All other data is derived
from it or cached externally. Restore by copying the backup `.duckdb` file back.

## Systemd User Unit (documentation only)

Create `~/.config/systemd/user/siempl.service`:

```ini
[Unit]
Description=siempl - agentic SIEM
After=network.target

[Service]
Type=simple
WorkingDirectory=%h/siempl
Environment=SIEMPL_HOME=%h/siempl/data
ExecStart=%h/siempl/.venv/bin/python -m siempl
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

Then: `systemctl --user enable --now siempl.service`

Note: `loginctl enable-linger` may be needed so the user service starts at boot
without a login session.

## Upgrading

```bash
cd ~/siempl
git pull
.venv/bin/pip install -e .
systemctl --user restart siempl
```

Database schema is auto-migrated on startup (`Database.init_schema()` runs
`CREATE TABLE IF NOT EXISTS` for all tables). No manual migration step is needed
for schema additions.

## Troubleshooting

### "Port already in use"
```bash
ss -tlnp | grep 8765   # Check what's using the port
```

### "Database is locked"
Only one siempl process may access the DuckDB file at a time. Kill any stale
processes before restarting.

### Web UI shows "module not available" for everything
Verify the package is installed correctly:
```bash
cd ~/siempl && .venv/bin/python -c "import siempl; print(siempl.__version__)"
```

### AI features not working
1. Check `Settings > AI Engine > Key Status` shows "found"
2. Verify `AI Engine` switch is ON
3. Check daily caps haven't been exceeded (shown on Settings page)
4. Ensure `agents_dry_run` is OFF if you want side effects

### Collectors not starting
Run without `--no-collectors` and check the startup log for collector messages.
Syslog ports 5514 require no other process binding them.

### Memory usage too high
DuckDB uses ~100MB RAM minimum. On a 7.7GB box, keep dataset under ~5GB.
Set retention on high-volume tables via the Ingestion page.
Consider dropping unnecessary tables if space is tight.