"""Log collectors: syslog server (UDP+TCP), HTTP ingest router, file tailer.

All collectors feed IngestPipeline in batches. Designed to run as asyncio tasks
or threads within the single siempl process.

Module-level API:
    SyslogServer(db, udp_port, tcp_port, source_id=None) - asyncio syslog server
    make_ingest_router(db) -> fastapi.APIRouter - POST /api/ingest/{source_id}
    FileTailer(db, source_id, path) - poll-based file tailer with inode/rotation handling
    CollectorManager(db) - thread-safe runtime start/stop for all collectors
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import struct
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timezone
from typing import Any, Optional

from ..audit import record as audit_record
from ..db import Database
from ..ingest import IngestPipeline, NormalizedEvent

logger = logging.getLogger(__name__)

# FastAPI imports at module level (needed for dependency injection)
try:
    from fastapi import APIRouter, Body, HTTPException, Request
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    APIRouter = None  # type: ignore
    HTTPException = None  # type: ignore
    Request = None  # type: ignore

# Module-level pipeline ref for the router endpoint (avoid closure issues)
_router_pipeline: IngestPipeline | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# ── Syslog server (UDP + TCP over asyncio) ────────────────────────────────────

class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP syslog receiver; queues raw messages for batch ingest."""

    def __init__(self, queue: asyncio.Queue, source_id: str):
        self.queue = queue
        self.source_id = source_id
        self.transport = None  # type: ignore

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            msg = data.decode("utf-8", errors="replace").rstrip("\n\r")
            self.queue.put_nowait((self.source_id, msg))
        except Exception:
            logger.debug("datagram_received: ignored error", exc_info=True)

    def error_received(self, exc):
        pass


class SyslogServer:
    """Async syslog server. Listens on UDP and TCP (with octet-counting and
    newline framing per RFC 6587), flushing events to IngestPipeline in batches.

    Usage:
        server = SyslogServer(db, source_id="my_syslog", udp_port=5514, tcp_port=5514)
        await server.start()
        ...
        await server.stop()
    """

    MAX_EVENTS_PER_MSG = 1        # one syslog message = one event
    FLUSH_SIZE = 500
    FLUSH_INTERVAL = 1.0          # seconds

    def __init__(self, db: Database, source_id: str = "syslog", udp_port: int = 5514, tcp_port: int = 5514):
        self.db = db
        self.pipeline = IngestPipeline(db)
        self.source_id = source_id
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self._queue: asyncio.Queue = asyncio.Queue()
        self._tcp_server: asyncio.AbstractServer | None = None
        self._udp_transport: Any = None
        self._batch_task: asyncio.Task | None = None
        self._running = False
        self.last_error: str | None = None
        self.events_total = 0
        self.started_at: str | None = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._running = True
        self.started_at = _utcnow().isoformat()

        # UDP listener
        try:
            self._udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self._queue, self.source_id),
                local_addr=("0.0.0.0", self.udp_port),
            )
        except OSError as e:
            self.last_error = f"UDP port {self.udp_port} unavailable: {e}"

        # TCP listener
        try:
            self._tcp_server = await asyncio.start_server(
                lambda r, w: asyncio.create_task(self._handle_tcp(r, w)),
                "0.0.0.0", self.tcp_port,
            )
        except OSError as e:
            self.last_error = f"TCP port {self.tcp_port} unavailable: {e}"

        # Background batch flusher
        self._batch_task = asyncio.create_task(self._batch_loop())

    async def stop(self) -> None:
        self._running = False
        if self._batch_task:
            try:
                await asyncio.wait_for(self._batch_task,
                                       timeout=self.FLUSH_INTERVAL + 5.0)
            except (TimeoutError, asyncio.CancelledError):
                self._batch_task.cancel()
                try:
                    await self._batch_task
                except asyncio.CancelledError:
                    pass

        if self._tcp_server:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

        if self._udp_transport:
            self._udp_transport.close()

        # Flush remaining
        await self._flush()

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """TCP syslog handler: supports octet-counting and newline framing."""
        buffer = b""
        source_id = self.source_id
        try:
            while self._running:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=30)
                except TimeoutError:
                    break
                if not chunk:
                    break
                buffer += chunk

                # Try octet-counting framing (RFC 6587 §3.4.1): <length> SP <message>
                while buffer:
                    idx = buffer.find(b" ")
                    if idx > 0:
                        try:
                            msg_len = int(buffer[:idx])
                            total_needed = idx + 1 + msg_len
                            if len(buffer) >= total_needed:
                                msg = buffer[idx + 1:total_needed].decode("utf-8", errors="replace").rstrip()
                                self._queue.put_nowait((source_id, msg))
                                buffer = buffer[total_needed:]
                                continue
                        except (ValueError, IndexError):
                            pass

                    # Try newline framing (RFC 6587 §3.4.2)
                    nl = buffer.find(b"\n")
                    if nl >= 0:
                        msg = buffer[:nl].decode("utf-8", errors="replace").rstrip("\r")
                        self._queue.put_nowait((source_id, msg))
                        buffer = buffer[nl + 1:]
                        continue

                    # Not enough data for either framing
                    break
        except Exception:
            logger.debug("_handle_tcp: ignored error", exc_info=True)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                logger.debug("_handle_tcp: ignored error", exc_info=True)

    async def _batch_loop(self) -> None:
        """Accumulate records and flush periodically."""
        batch: dict[str, list[str]] = {}
        last_flush = time.monotonic()
        try:
            while True:
                try:
                    sid, msg = await asyncio.wait_for(self._queue.get(), timeout=self.FLUSH_INTERVAL)
                    batch.setdefault(sid, []).append(msg)
                except TimeoutError:
                    pass

                total = sum(len(v) for v in batch.values())
                if (self._running and total < self.FLUSH_SIZE
                        and time.monotonic() - last_flush < self.FLUSH_INTERVAL):
                    continue
                if not batch and self._running:
                    continue
                if batch:
                    await self._flush_batch(batch)
                    batch.clear()
                    last_flush = time.monotonic()
                if not self._running:
                    break
        finally:
            if batch:
                try:
                    await asyncio.shield(self._flush_batch(batch))
                except asyncio.CancelledError:
                    pass
                batch.clear()

    async def _flush_batch(self, batch: dict[str, list[str]]) -> None:
        """Ingest one batch per source_id."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._ingest_batch_sync, batch)

    def _ingest_batch_sync(self, batch: dict[str, list[str]]) -> None:
        for sid, msgs in batch.items():
            if not msgs:
                continue
            result = self.pipeline.ingest(sid, msgs)
            self.events_total += result.inserted

    async def _flush(self) -> None:
        """Drain all queued messages."""
        batch: dict[str, list[str]] = {}
        while not self._queue.empty():
            try:
                sid, msg = self._queue.get_nowait()
                batch.setdefault(sid, []).append(msg)
            except asyncio.QueueEmpty:
                break
        if batch:
            await self._flush_batch(batch)


# ── HTTP ingest router (FastAPI APIRouter) ──────────────────────────────────

# Module-level endpoint (avoids FastAPI dependency injection bug in closures)
async def _ingest_endpoint(
    request: Request,
    source_id: str,
    parser: str | None = None,
):
    """POST /api/ingest/{source_id} — ingest JSON object, array, or NDJSON."""
    pipeline = _router_pipeline
    if pipeline is None:
        raise HTTPException(500, "Ingest pipeline not initialized")

    MAX_BODY_BYTES = 5_000_000
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "Payload too large")

    # Token enforcement for HTTP sources
    src = db_from_pipeline(pipeline).query_one(
        "SELECT kind, status, config FROM sources WHERE source_id=?", [source_id])
    if src:
        config = src.get("config") or {}
        if isinstance(config, str):
            config = json.loads(config)
        if src.get("kind") == "http":
            # Check paused
            if src.get("status") == "paused":
                raise HTTPException(409, "Source is paused")
            # Token enforcement
            token = config.get("token", "") if isinstance(config, dict) else ""
            if token:
                auth = request.headers.get("Authorization", "")
                x_token = request.headers.get("X-Siempl-Token", "")
                bearer = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else ""
                if bearer != token and x_token != token:
                    raise HTTPException(401, "Unauthorized: token required")
    else:
        # Unknown source may be auto-created; don't enforce token here
        pass

    text = body.decode("utf-8", errors="replace")
    records: list = []

    stripped = text.strip()
    if stripped.startswith("["):
        try:
            arr = json.loads(stripped)
            records = arr if isinstance(arr, list) else [arr]
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"Invalid JSON array: {e}")
    elif stripped.startswith("{"):
        lines = stripped.split("\n")
        json_lines = [l for l in lines if l.strip()]
        if len(json_lines) > 1:
            for line in json_lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise HTTPException(400, f"Invalid NDJSON line: {e}")
        else:
            try:
                records = [json.loads(stripped)]
            except json.JSONDecodeError as e:
                raise HTTPException(400, f"Invalid JSON: {e}")
    else:
        raise HTTPException(400, "Body must be JSON object, array, or NDJSON")

    result = pipeline.ingest(source_id, records, parser=parser)
    return {
        "received": result.received,
        "inserted": result.inserted,
        "dropped": result.dropped,
        "failed": result.failed,
        "tables": result.tables,
        "errors": result.errors,
    }


def db_from_pipeline(pipeline: IngestPipeline) -> Database:
    """Access the database from a pipeline instance."""
    # Pipeline exposes _db internally
    return getattr(pipeline, "_db", None)  # type: ignore


def make_ingest_router(db: Database) -> Any:
    """Build a FastAPI APIRouter with a POST /api/ingest/{source_id} endpoint.

    Accepts JSON object, JSON array, or NDJSON.  Body capped at 5 MB.
    """
    if not _FASTAPI_AVAILABLE:
        raise ImportError("fastapi is required for HTTP ingest")

    global _router_pipeline
    _router_pipeline = IngestPipeline(db)

    router = APIRouter(prefix="/api/ingest", tags=["ingest"])
    router.post("/{source_id}")(_ingest_endpoint)
    return router


# ── File tailer ───────────────────────────────────────────────────────────────

class FileTailer(threading.Thread):
    """Poll-based file tailer with inode rotation handling and offset persistence.

    Tracks position via an offset stored in the sources.config JSON.
    Handles log rotation by detecting inode changes and re-opening.

    Usage:
        tailer = FileTailer(db, "my_source", "/var/log/auth.log")
        tailer.start()
    """

    POLL_INTERVAL = 1.0
    FLUSH_SIZE = 500
    FLUSH_INTERVAL = 5.0

    def __init__(self, db: Database, source_id: str, path: str):
        super().__init__(daemon=True, name=f"tailer-{source_id}")
        self.db = db
        self.pipeline = IngestPipeline(db)
        self.source_id = source_id
        self.path = path
        self._stop_event = threading.Event()
        self._running = False
        self.last_error: str | None = None
        self.events_total = 0
        self.started_at: str | None = None

    def run(self) -> None:
        self._running = True
        self.started_at = _utcnow().isoformat()
        self._tail()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()

    def _load_offset(self) -> int:
        """Load the last known offset from sources.config."""
        src = self.db.query_one("SELECT config FROM sources WHERE source_id=?",
                                [self.source_id])
        config = src.get("config") if src else None
        if isinstance(config, str):
            config = json.loads(config)
        if isinstance(config, dict):
            return int(config.get("offset", 0))
        return 0

    def _save_offset(self, offset: int, inode: int) -> None:
        """Save current offset + inode to sources.config."""
        config = json.dumps({"offset": offset, "inode": inode})
        self.db.execute(
            "UPDATE sources SET config=? WHERE source_id=?",
            [config, self.source_id])

    def _tail(self) -> None:
        offset = self._load_offset()
        current_inode = self._get_inode()
        last_flush = time.monotonic()
        batch: list[str] = []

        while self._running:
            try:
                time.sleep(self.POLL_INTERVAL)
                if not os.path.exists(self.path):
                    continue

                # Check for rotation (inode changed)
                new_inode = self._get_inode()
                if new_inode and new_inode != current_inode:
                    # File was rotated: finish reading old, then reset
                    if current_inode:
                        self._read_remaining(current_inode, offset)
                    current_inode = new_inode
                    offset = 0

                if not current_inode:
                    current_inode = new_inode or 0

                # Read new data
                messages, new_offset = self._read_chunk(offset)
                if messages:
                    batch.extend(messages)
                    offset = new_offset

                # Flush on size or interval
                if batch and (len(batch) >= self.FLUSH_SIZE or
                              time.monotonic() - last_flush >= self.FLUSH_INTERVAL):
                    self._flush_batch(batch)
                    batch.clear()
                    last_flush = time.monotonic()

                # Periodic offset save
                if offset != self._load_offset():
                    self._save_offset(offset, current_inode)

            except Exception as exc:
                self.last_error = str(exc)

        # Final flush
        if batch:
            self._flush_batch(batch)
        self._save_offset(offset, current_inode)

    def _get_inode(self) -> int | None:
        try:
            return os.stat(self.path).st_ino
        except OSError:
            return None

    def _read_chunk(self, offset: int) -> tuple[list[str], int]:
        """Read new lines from file at offset. Returns (messages, new_offset)."""
        messages: list[str] = []
        try:
            with open(self.path, errors="replace") as f:
                f.seek(offset)
                for line in f:
                    line = line.rstrip("\n\r")
                    if line:
                        messages.append(line)
                new_offset = f.tell()
        except OSError:
            return [], offset
        return messages, new_offset

    def _read_remaining(self, inode: int, offset: int) -> None:
        """Finish reading old inode to EOF before switching."""
        try:
            with open(self.path, errors="replace") as f:
                try:
                    if os.fstat(f.fileno()).st_ino == inode:
                        f.seek(offset)
                        messages = [l.rstrip("\n\r") for l in f if l.strip()]
                        if messages:
                            self._flush_batch(messages)
                except OSError:
                    pass
        except OSError:
            pass

    def _flush_batch(self, messages: list[str]) -> None:
        """Send a batch of lines through the pipeline."""
        if not messages:
            return
        result = self.pipeline.ingest(self.source_id, messages)
        self.events_total += result.inserted


# ── CollectorManager (runtime start/stop) ───────────────────────────────────

class _AsyncLoopThread(threading.Thread):
    """Background thread that owns an asyncio event loop."""
    daemon = True

    def __init__(self):
        super().__init__(name="siempl-collector-loop")
        self.loop: asyncio.AbstractEventLoop | None = None
        self._ready = threading.Event()
        self._shutdown = threading.Event()

    def run(self) -> None:
        loop = asyncio.new_event_loop()
        self.loop = loop
        try:
            self._ready.set()
            loop.run_forever()
        finally:
            try:
                loop.close()
            except Exception:
                logger.debug("run: ignored error", exc_info=True)

    def run_coroutine(self, coro):
        if self.loop is None:
            raise RuntimeError("Async loop thread not started")
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=10)

    def stop(self):
        self._shutdown.set()
        if self.loop is not None:
            loop = self.loop
            # schedule graceful shutdown
            loop.call_soon_threadsafe(loop.stop)


class CollectorManager:
    """Manages active collectors at runtime without restarting the process.

    Attach to app.state.collector_manager to allow the web layer to
    start/stop syslog and file tailers on demand.

    Thread-safe: all public methods acquire the internal lock.
    """

    def __init__(self, db: Database):
        self.db = db
        self._file_tailers: dict[str, FileTailer] = {}
        self._syslog_servers: dict[str, SyslogServer] = {}
        self._lock = threading.RLock()
        self._loop_thread: _AsyncLoopThread | None = None
        self._running = True

    def start(self, source_id: str) -> dict:
        """Start a collector for the given source_id. Returns status dict."""
        with self._lock:
            src = self.db.query_one(
                "SELECT source_id, kind, config, status FROM sources WHERE source_id=?",
                [source_id])
            if src is None:
                return {"ok": False, "error": "Source not found", "running": False}

            kind = src.get("kind", "")
            config = src.get("config") or {}
            if isinstance(config, str):
                config = json.loads(config)

            if kind == "file":
                path = config.get("path", "") if isinstance(config, dict) else ""
                if not path or not os.path.exists(path):
                    return {"ok": False, "error": f"File path does not exist: {path}", "running": False}
                if source_id in self._file_tailers:
                    return {"ok": True, "running": True}
                tailer = FileTailer(self.db, source_id, path)
                tailer.start()
                self._file_tailers[source_id] = tailer
                return {"ok": True, "running": True}

            if kind == "syslog":
                if source_id in self._syslog_servers:
                    return {"ok": True, "running": True}
                udp_port = int(config.get("udp_port", 5514)) if isinstance(config, dict) else 5514
                tcp_port = int(config.get("tcp_port", 5514)) if isinstance(config, dict) else 5514

                if self._loop_thread is None or not self._loop_thread.is_alive():
                    self._loop_thread = _AsyncLoopThread()
                    self._loop_thread.start()
                    self._loop_thread._ready.wait(timeout=5)

                server = SyslogServer(self.db, source_id=source_id, udp_port=udp_port, tcp_port=tcp_port)
                try:
                    self._loop_thread.run_coroutine(server.start())
                except OSError as exc:
                    server.last_error = str(exc)
                    return {"ok": False, "error": str(exc), "running": False, "last_error": server.last_error}

                if server.last_error:
                    return {"ok": False, "error": server.last_error, "running": False, "last_error": server.last_error}

                self._syslog_servers[source_id] = server
                return {"ok": True, "running": True}

            if kind in ("http", "testdata"):
                # HTTP is handled by the FastAPI route; testdata isn't runtime-collected
                return {"ok": True, "running": True}

            return {"ok": False, "error": f"Unknown kind: {kind}", "running": False}

    def stop(self, source_id: str) -> dict:
        """Stop a collector for the given source_id."""
        with self._lock:
            src = self.db.query_one(
                "SELECT kind FROM sources WHERE source_id=?", [source_id])
            if src is None:
                return {"ok": False, "error": "Source not found", "running": False}

            kind = src.get("kind", "")
            if kind == "file":
                tailer = self._file_tailers.pop(source_id, None)
                if tailer:
                    tailer.stop()
                    tailer.join(timeout=3)
                return {"ok": True, "running": False}

            if kind == "syslog":
                server = self._syslog_servers.pop(source_id, None)
                if server:
                    try:
                        if self._loop_thread and self._loop_thread.loop and self._loop_thread.is_alive():
                            self._loop_thread.run_coroutine(server.stop())
                    except Exception:
                        logger.debug("stop: ignored error", exc_info=True)
                return {"ok": True, "running": False}

            return {"ok": True, "running": False}

    def status(self) -> dict:
        """Return per-source status: {source_id: {running, listening_ports, last_error, events_since_start}}."""
        with self._lock:
            result: dict[str, dict] = {}
            for sid, tailer in self._file_tailers.items():
                result[sid] = {
                    "running": tailer._running,
                    "listening_ports": None,
                    "last_error": tailer.last_error,
                    "events_since_start": tailer.events_total,
                }
            for sid, server in self._syslog_servers.items():
                result[sid] = {
                    "running": server._running,
                    "listening_ports": {"udp": server.udp_port, "tcp": server.tcp_port},
                    "last_error": server.last_error,
                    "events_since_start": server.events_total,
                }
            return result

    def stop_all(self) -> None:
        """Stop all collectors and the async loop thread."""
        with self._lock:
            self._running = False
            for sid, tailer in list(self._file_tailers.items()):
                tailer.stop()
                tailer.join(timeout=3)
            self._file_tailers.clear()

            # Stop syslogs
            for sid, server in list(self._syslog_servers.items()):
                try:
                    if self._loop_thread and self._loop_thread.loop and self._loop_thread.is_alive():
                        self._loop_thread.run_coroutine(server.stop())
                except Exception:
                    logger.debug("stop_all: ignored error", exc_info=True)
            self._syslog_servers.clear()

            if self._loop_thread:
                self._loop_thread.stop()
                self._loop_thread.join(timeout=5)
                self._loop_thread = None


# ── collector runner (legacy, used by __main__) ──────────────────────────────

def start_collectors(db: Database) -> list[FileTailer]:
    """Start all enabled collectors for sources of kind 'file'.

    Returns a list of started threads (may be empty).
    Syslog/HTTP are now managed by CollectorManager at runtime.
    """
    threads: list[FileTailer] = []

    try:
        sources = db.query(
            "SELECT source_id, kind, config FROM sources WHERE status='active' AND kind IN ('syslog','http','file')")
    except Exception:
        return threads

    for src in sources:
        source_id = src["source_id"]
        kind = src["kind"]
        config = src.get("config") or {}
        if isinstance(config, str):
            config = json.loads(config)

        if kind == "file":
            filepath = config.get("path", "")
            if filepath and os.path.exists(filepath):
                tailer = FileTailer(db, source_id, filepath)
                tailer.start()
                threads.append(tailer)

    return threads
