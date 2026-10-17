"""Remediation connectors – stub implementations only. See docs/AGENTS.md for the design.

SAFETY (non-negotiable): every connector in this module is a STUB. It logs to
remediation_log with dry_run=True and result='stub: would <action>'. It MUST
NEVER touch the host system, even when dry_run=False and remediation_enabled=True.
This is intentional: real remediation connectors require a safety review, operator
approval, and tested rollback. See "Adding a real connector" in docs/AGENTS.md.

Connectors:
  block_ip(ip, ...)       - stub
  disable_user(user, ...) - stub
  isolate_host(host, ...) - stub
  kill_process(pid, ...)  - stub

The registry allows registering new connectors dynamically. Every connector follows
the signature: (db: Database, target: str, **kwargs) -> dict (result dict with
status, message, dry_run).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from ..db import Database, new_id

logger = logging.getLogger(__name__)

# Type for a remediation connector function
RemediationConnector = Callable[..., dict[str, Any]]


class ConnectorRegistry:
    """Register and invoke named remediation connectors.

    All built-in connectors are stubs. Real connectors must be registered explicitly.
    """

    def __init__(self):
        self._connectors: dict[str, RemediationConnector] = {}

    def register(self, name: str, fn: RemediationConnector) -> None:
        """Register a connector function under `name`."""
        self._connectors[name] = fn

    def get(self, name: str) -> RemediationConnector | None:
        """Return a connector by name, or None."""
        return self._connectors.get(name)

    def list_names(self) -> list[str]:
        """Return sorted list of registered connector names."""
        return sorted(self._connectors.keys())

    def invoke(self, db: Database, name: str, target: str, *,
               alert_id: str = "", dry_run: bool = True,
               **kwargs) -> dict[str, Any]:
        """Invoke a connector by name, logging to remediation_log.

        Args:
            db: Database instance
            name: Connector name (e.g. 'block_ip')
            target: Target of the action (ip address, username, hostname, pid)
            alert_id: Associated alert ID for audit trail
            dry_run: Whether to actually execute (always True for stubs!)
            **kwargs: Additional connector-specific args

        Returns:
            dict with keys: status, message, action_id, dry_run
        """
        fn = self._connectors.get(name)
        if fn is None:
            action_id = new_id("rem_")
            db.execute(
                "INSERT INTO remediation_log(action_id,alert_id,agent,action,target,dry_run,result) "
                "VALUES (?,?,?,?,?,?,?)",
                [action_id, alert_id, "remediation", name, target, dry_run,
                 f"unknown connector: {name}"])
            return {"status": "error", "message": f"unknown connector: {name}",
                    "action_id": action_id, "dry_run": dry_run}

        return fn(db, target, alert_id=alert_id, dry_run=dry_run, **kwargs)


# ---- Stub connectors -----------------------------------------------------------

def _log_stub(db: Database, action: str, target: str, *, alert_id: str = "",
              dry_run: bool = True, **kwargs) -> dict[str, Any]:
    """Common logging for all stub connectors. Always sets dry_run=True regardless of input."""
    action_id = new_id("rem_")
    message = f"stub: would {action} target={target}"
    if kwargs:
        message += f" kwargs={kwargs}"
    # ALWAYS log as dry_run=True — stubs never execute
    db.execute(
        "INSERT INTO remediation_log(action_id,alert_id,agent,action,target,dry_run,result) "
        "VALUES (?,?,?,?,?,?,?)",
        [action_id, alert_id, "remediation", action, target, True, message])
    return {"status": "stub", "message": message, "action_id": action_id, "dry_run": True}


def block_ip(db: Database, ip: str, *, alert_id: str = "", dry_run: bool = True,
             **kwargs) -> dict[str, Any]:
    """Log intent to block an IP. STUB: never blocks anything.

    Real implementation checklist (see docs/AGENTS.md):
      1. Confirm the IP is not in an allowlist
      2. Verify the IP is not internal/RFC1918
      3. Obtain operator approval (or agent policy permits)
      4. Execute via firewall API / iptables / security group
      5. Log the actual firewall rule ID in result
      6. Set up auto-expiry (rule removed after TTL)
      7. Record rollback procedure
    """
    return _log_stub(db, "block_ip", ip, alert_id=alert_id, dry_run=True, **kwargs)


def disable_user(db: Database, user: str, *, alert_id: str = "", dry_run: bool = True,
                 **kwargs) -> dict[str, Any]:
    """Log intent to disable a user account. STUB: never disables anyone.

    Real implementation checklist:
      1. Confirm the user exists and is not a protected account
      2. Verify the user is not currently in an active session
      3. Obtain operator approval
      4. Execute via LDAP/AD API / pam / passwd -l
      5. Log the actual account status change
      6. Record rollback (re-enable) procedure
    """
    return _log_stub(db, "disable_user", user, alert_id=alert_id, dry_run=True, **kwargs)


def isolate_host(db: Database, host: str, *, alert_id: str = "", dry_run: bool = True,
                 **kwargs) -> dict[str, Any]:
    """Log intent to isolate a host. STUB: never isolates anything.

    Real implementation checklist:
      1. Confirm host exists and is not critical infrastructure
      2. Verify isolation won't partition the network
      3. Obtain operator approval
      4. Execute via network ACL / firewall / EDR API
      5. Log the actual isolation rule/action
      6. Record rollback (de-isolate) procedure
    """
    return _log_stub(db, "isolate_host", host, alert_id=alert_id, dry_run=True, **kwargs)


def kill_process(db: Database, pid: str, *, alert_id: str = "", dry_run: bool = True,
                 **kwargs) -> dict[str, Any]:
    """Log intent to kill a process. STUB: never kills anything.

    Real implementation checklist:
      1. Confirm PID still exists and matches expected process
      2. Verify process is not system-critical
      3. Obtain operator approval
      4. Execute via EDR API / SSH + kill / taskkill
      5. Log actual kill result
      6. No rollback needed (but check for respawn)
    """
    return _log_stub(db, "kill_process", pid, alert_id=alert_id, dry_run=True, **kwargs)


# ---- Global registry -----------------------------------------------------------

_registry: ConnectorRegistry | None = None


def get_registry() -> ConnectorRegistry:
    """Return the global ConnectorRegistry, initialising it with stub connectors."""
    global _registry
    if _registry is None:
        _registry = ConnectorRegistry()
        _registry.register("block_ip", block_ip)
        _registry.register("disable_user", disable_user)
        _registry.register("isolate_host", isolate_host)
        _registry.register("kill_process", kill_process)
    return _registry
