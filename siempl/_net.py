"""Listening-socket helpers for the web server (kept out of __main__ to hold its complexity down)."""
from __future__ import annotations

import socket


def resolve_host(all_interfaces: bool, configured: str) -> str:
    """Bind address: '::' (IPv6 plus IPv4) when --host is given and IPv6 exists, else the configured address."""
    if all_interfaces:
        return "::" if socket.has_ipv6 else "0.0.0.0"
    return configured


def listen_sockets(host: str, port: int) -> list[socket.socket] | None:
    """A dual-stack socket for '::' (IPV6_V6ONLY explicitly off); None for any other host.

    uvicorn's own bind to '::' came up IPv6-only on this box, so we create the socket ourselves.
    This is what lets 10.x LAN clients and IPv6-only names like xiaohongshu.local both connect.
    """
    if host != "::":
        return None
    return [socket.create_server((host, port), family=socket.AF_INET6, dualstack_ipv6=True, backlog=2048)]
