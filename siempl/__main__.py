"""siempl entry point: `python -m siempl [--host --port --no-collectors --no-scheduler]`

Starts the full application: database, collectors (optional), rule scheduler
(optional), agent scheduler (optional), and the FastAPI web server on
127.0.0.1:8765 by default (never 0.0.0.0 unless --host is given).
"""
from __future__ import annotations

import argparse
import signal
import threading

from siempl._net import listen_sockets, resolve_host


def main() -> None:
    ap = argparse.ArgumentParser(prog="siempl", description="siempl — agentic SIEM")
    ap.add_argument("--host", action="store_true", help="Bind to all interfaces (:: dual-stack, or 0.0.0.0 without IPv6) instead of 127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="Override bind port (default from settings, 8765)")
    ap.add_argument("--no-collectors", action="store_true", help="Do not start log collectors (syslog/http/file)")
    ap.add_argument("--no-scheduler", action="store_true", help="Do not start the rule/agent schedulers")
    args = ap.parse_args()

    # Bootstrap
    from siempl.db import Database
    db = Database()
    settings = {k: db.get_setting(k, v) for k, v in _HOST_DEFAULTS.items()}

    host = resolve_host(args.host, settings.get("bind_host", "127.0.0.1"))
    port = args.port or settings.get("bind_port", 8765)
    threads: list[threading.Thread] = []

    # -- Collectors ----------------------------------------------------------
    if not args.no_collectors:
        try:
            from siempl.collectors import start_collectors  # type:ignore[import-untyped]
            ct = start_collectors(db)
            for t in ct:
                t.start() if not t.is_alive() else None
                threads.append(t)
            print(f"[siempl] started {len(ct)} collector(s)")
        except (ImportError, AttributeError) as e:
            print(f"[siempl] collectors not available ({e}); run with --no-collectors to suppress")

    # -- Rule scheduler ------------------------------------------------------
    if not args.no_scheduler and settings.get("rule_scheduler_enabled", True):
        try:
            from siempl.detect import start_scheduler  # type:ignore[import-untyped]
            st = start_scheduler(db)
            st.start() if not st.is_alive() else None
            threads.append(st)
            print("[siempl] rule scheduler started")
        except (ImportError, AttributeError) as e:
            print(f"[siempl] rule scheduler not available ({e}); run with --no-scheduler to suppress")

    # -- Agent scheduler -----------------------------------------------------
    if not args.no_scheduler:
        try:
            from siempl.agents.scheduler import start_agent_scheduler  # type:ignore[import-untyped]
            ast = start_agent_scheduler(db)
            ast.start() if not ast.is_alive() else None
            threads.append(ast)
            print("[siempl] agent scheduler started")
        except (ImportError, AttributeError):
            pass  # optional

    # -- CollectorManager (shared with web app) ----------------------------
    from siempl.collectors import CollectorManager
    collector_manager = CollectorManager(db)

    # -- Web app -------------------------------------------------------------
    from siempl.web import create_app
    app = create_app(db, collector_manager=collector_manager)

    import uvicorn
    print(f"[siempl] starting web server on http://{host}:{port}")
    config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config)

    # Graceful shutdown
    def shutdown(*_):
        print("\n[siempl] shutting down…")
        server.should_exit = True

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    server.run(sockets=listen_sockets(host, port))

    for t in threads:
        t.join(timeout=3)
    db.close()
    print("[siempl] stopped.")


_HOST_DEFAULTS = {
    "bind_host": "127.0.0.1",
    "bind_port": 8765,
    "rule_scheduler_enabled": True,
}


if __name__ == "__main__":
    main()
